package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/golang/glog"

	"github.com/aeden/traceroute"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iap/v1"
	oauthsvc "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type gceVMSpec struct {
	InstanceCreationTimestamp int64           `json:"instance_creation_timestamp,omitempty"`
	InstanceID                string          `json:"instance_id,omitempty"`
	InstanceName              string          `json:"instance_name,omitempty"`
	ProjectID                 string          `json:"project_id,omitempty"`
	Zone                      string          `json:"zone,omitempty"`
	ServiceAccount            []string        `json:"service_account,omitempty"`
	ExternalIP                string          `json:"external_ip,omitempty"`
	OSLogin                   string          `json:"os_login,omitempty"`
	OSLogin2FA                string          `json:"os_login_2fa,omitempty"`
	SSHPubKeys                []ssh.PublicKey `json:"ssh_pub_keys,omitempty"`
	HasMetadataPermissions    bool            `json:"has_metadata_permisssion,omitempty"`
	HasAdminPermissions       bool            `json:"has_admin_permisssion,omitempty"`
}

type projectSpec struct {
	ProjectID  string          `json:"project_id,omitempty"`
	OSLogin    string          `json:"os_login,omitempty"`
	OSLogin2FA string          `json:"os_login_2fa,omitempty"`
	SSHPubKeys []ssh.PublicKey `json:"ssh_pub_keys,omitempty"`
}

type saSpec struct {
	ProjectID      string   `json:"project_id,omitempty"`
	ServiceAccount string   `json:"service_account,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
}

type iapSpec struct {
	ProjectID   string   `json:"project_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

var (
	instance         = flag.String("instance", "eternal", "GCE Instance")
	projectID        = flag.String("project", "fabled-ray-104117", "ProjectID")
	zone             = flag.String("zone", "us-central1-a", "Zone")
	port             = flag.Int("port", 22, "Port")
	accessToken      = flag.String("access_token", "", "Access token from `gcloud auth print-access-token`")
	sshPub           = flag.String("sshPub", "", "SSHPublic Key File")
	sshPrivKey       = flag.String("sshPrivKey", "", "SSHPublic Key File")
	sshKnownHosts    = flag.String("sshKnownHosts", "", "SSH known Hosts")
	enableTraceRoute = flag.Bool("enableTraceRoute", false, "Enable Traceroute (may require sudo)")
	verifyIAPTunnel  = flag.Bool("verifyIAPTunnel", false, "Run IAP Tunnel Tests")
	noverifySSH      = flag.Bool("noverifySSH", true, "Verify SSH connectivity")
	adminRole        = flag.String("adminRole", "roles/compute.instanceAdmin.v1", "Admin roleto VMs")
	connectUserName  = flag.String("connectUserName", "", "Connect as user")
)

const (
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

func getUser(ctx context.Context, tokenSrc oauth2.TokenSource) (user *oauthsvc.Userinfo, err error) {

	glog.V(30).Infof("    Getting gcloud credentials")
	client := oauth2.NewClient(context.Background(), tokenSrc)
	service, err := oauthsvc.New(client)
	if err != nil {
		return nil, fmt.Errorf("Unable to create api service: %v", err)
	}
	ui, err := service.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("Unable to get userinfo: %v", err)
	}
	glog.V(30).Infof("UserInfo: %v", ui)

	return ui, nil
}

func getInstance(ctx context.Context, tokenSrc oauth2.TokenSource, instanceID, projectID, zone string) (crep *gceVMSpec, err error) {
	glog.V(2).Infof("     Getting instance [%s] in project,zone: [%s,%s]", instanceID, projectID, zone)
	ret := &gceVMSpec{}
	computeService, err := compute.NewService(ctx, option.WithTokenSource(tokenSrc))
	if err != nil {
		return nil, fmt.Errorf("Could not create ComputeClient %v", err)
	}

	cresp, err := computeService.Instances.Get(projectID, zone, instanceID).Do()
	if err != nil {
		glog.Errorf("      ERROR:  user does not have [compute.instances.get] permission on VM: [%s]", instanceID)
		return nil, fmt.Errorf("InstanceID not Found using GCE API %v", err)
	}
	ret.InstanceID = strconv.FormatUint(cresp.Id, 10)

	glog.V(2).Infof("      Found  VM instanceID %#v\n", strconv.FormatUint(cresp.Id, 10))
	glog.V(30).Infof("      Found  VM CreationTimestamp %#v\n", cresp.CreationTimestamp)
	glog.V(30).Infof("      Found  VM Fingerprint %#v\n", cresp.Fingerprint)

	for _, sa := range cresp.ServiceAccounts {
		glog.V(2).Infof("      Found  VM ServiceAccount %#v\n", sa.Email)
		ret.ServiceAccount = append(ret.ServiceAccount, sa.Email)
	}

	for _, ni := range cresp.NetworkInterfaces {
		for _, ac := range ni.AccessConfigs {
			if ac.Type == "ONE_TO_ONE_NAT" {
				if ac.NatIP == "" {
					glog.V(20).Infof("      VM does not have external IP")
				} else {
					glog.V(20).Infof("      Found Registered External IP Address: %s", ac.NatIP)
					ret.ExternalIP = ac.NatIP
				}
			}
		}
	}

	for _, m := range cresp.Metadata.Items {
		if strings.ToLower(m.Key) == "ssh-keys" {
			glog.V(99).Infof("      Found Instance SSH Key %s", *m.Value)

			keys := strings.Split(*m.Value, "\n")
			for _, v := range keys {
				parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v))
				if err != nil {
					glog.Error("      Could not parse SSH Key %s", v, err)
				}
				glog.V(99).Infof("     %v", ssh.FingerprintSHA256(parsedKey))
				ret.SSHPubKeys = append(ret.SSHPubKeys, parsedKey)
			}

		}
		if strings.ToLower(m.Key) == "enable-oslogin" {
			glog.V(20).Infof("      Found Instance OSLogin %s", *m.Value)
			ret.OSLogin = *m.Value
		}
		if strings.ToLower(m.Key) == "enable-oslogin-2fa" {
			glog.V(20).Infof("      Found Instance OSLogin2FA %s", *m.Value)
			ret.OSLogin2FA = *m.Value
		}
	}

	perms := []string{"compute.instances.setMetadata", "compute.instances.use"}
	if ret.OSLogin != "" {
		perms = append(perms, "compute.instances.osLogin")
	}
	glog.V(2).Infof("      Testing IAM Permissions %s", perms)
	iamResp, err := computeService.Instances.TestIamPermissions(projectID, zone, instanceID, &compute.TestPermissionsRequest{
		Permissions: perms,
	}).Do()
	if err != nil {
		glog.V(2).Infof("      Error getting IAM Permissions on VM: %s", err)
	}

	if !containsInSlice(iamResp.Permissions, "compute.instances.osLogin") && ret.OSLogin != "" {
		glog.Error("      ERROR: OS Login enabled but %s is missing ", iamResp.Permissions)
	} else {
		glog.V(2).Infof("      Verified IAM Permissions %s", iamResp.Permissions)
	}
	return ret, nil
}

func getServiceAccount(ctx context.Context, tokenSrc oauth2.TokenSource, projectID string, serviceAccounts []string) (crep *saSpec, err error) {

	glog.V(2).Infof("    Reading Project, ServiceAccount: %s, %s", projectID, serviceAccounts)
	ret := &saSpec{}
	iamService, err := iam.NewService(ctx, option.WithTokenSource(tokenSrc))

	if err != nil {
		return nil, fmt.Errorf("Could not create IAM Client %v", err)
	}

	rs := iam.NewProjectsServiceAccountsService(iamService)
	perms := []string{"iam.serviceAccounts.actAs", "iam.serviceAccounts.get"}
	resp, err := rs.TestIamPermissions(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, serviceAccounts[0]), &iam.TestIamPermissionsRequest{
		Permissions: perms,
	}).Context(ctx).Do()
	if err != nil {
		glog.V(2).Infof("      Could Not Read serviceAccount.  Ensure user has atleast iam.serviceAccounts.get permissions ")
		return nil, fmt.Errorf("Could not Read serviceAccount %v", err)
	}
	glog.V(2).Infof("     User has following permissions on serviceAccount %v", resp.Permissions)
	if !containsInSlice(resp.Permissions, "iam.serviceAccounts.actAs") {
		glog.Error("      ERROR: Service account %v is missing iam.serviceAccounts.actAs permission", serviceAccounts[0])
		return nil, fmt.Errorf("ERROR: Service account %v is missing iam.serviceAccounts.actAs permission", serviceAccounts[0])
	}
	return ret, nil
}

func getIAP(ctx context.Context, tokenSrc oauth2.TokenSource, projectID string, zone string, instance string) (crep *iapSpec, err error) {

	glog.V(2).Infof("    Reading IAP Config for Resource, : [%s, %s]", projectID, (fmt.Sprintf("projects/%s/iap_tunnel/zones/%s/instances/%s", projectID, zone, instance)))
	ret := &iapSpec{}

	iapService, err := iap.NewService(ctx, option.WithTokenSource(tokenSrc))

	if err != nil {
		return nil, fmt.Errorf("Could not create IAM Client %v", err)
	}

	perms := []string{"iap.tunnelInstances.accessViaIAP"}
	resp, err := iapService.V1.TestIamPermissions(fmt.Sprintf("projects/%s/iap_tunnel/zones/%s/instances/%s", projectID, zone, instance), &iap.TestIamPermissionsRequest{
		Permissions: perms,
	}).Context(ctx).Do()
	if err != nil {
		glog.V(2).Infof("      Could Not Read IAP IAM.  Ensure user has atleast iap.tunnelInstances.accessViaIAP  permissions ")
		return nil, fmt.Errorf("Could not Read IAP %v", err)
	}
	glog.V(2).Infof("     User has IAP permissions on VM: %v", resp.Permissions)
	return ret, nil
}

func getPermissionsInRole(ctx context.Context, tokenSrc oauth2.TokenSource, projectID, role string) (permissions []string, err error) {
	glog.V(20).Infof("      Getting Permissions for Role [%s]", role)
	iamService, err := iam.NewService(ctx, option.WithTokenSource(tokenSrc))

	if err != nil {
		return nil, fmt.Errorf("Could not create IAM Client %v", err)
	}

	rs := iam.NewRolesService(iamService)
	r, err := rs.Get(role).Do()
	if err != nil {
		return nil, fmt.Errorf("Could not read permissions in role %v", err)
	}
	return r.IncludedPermissions, nil
}

func getProject(ctx context.Context, tokenSrc oauth2.TokenSource, projectID string) (crep *projectSpec, err error) {
	glog.V(2).Infof("    Reading project: [%s]", projectID)
	ret := &projectSpec{}
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(tokenSrc))
	if err != nil {
		return nil, fmt.Errorf("Could not create CloudResourceManager Client %v", err)
	}

	resp, err := crmService.Projects.Get(projectID).Context(ctx).Do()
	if err != nil {
		glog.V(2).Infof("      Could Not Read project.  Ensure user has atleast compute.projects.get permissions (iam/")
		return nil, fmt.Errorf("Could not Read Project %v", err)
	}
	glog.V(2).Infof("     Found  ProjectID %#v\n", resp.ProjectId)
	glog.V(20).Infof("     Found  ProjectNumber %#v\n", resp.ProjectNumber)
	glog.V(20).Infof("     Found  State %#v\n", resp.LifecycleState)
	glog.V(20).Infof("     Found  Parent %#v\n", resp.Parent)

	// https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys#before-you-begin
	glog.V(2).Infof("     Testing if user has Project level metadata permissions [compute.projects.setCommonInstanceMetadata]")

	perms := []string{"compute.projects.setCommonInstanceMetadata"}
	rr, err := crmService.Projects.TestIamPermissions(projectID, &cloudresourcemanager.TestIamPermissionsRequest{
		Permissions: perms,
	}).Context(ctx).Do()
	if err != nil {
		glog.V(2).Infof("      Could Not Read serviceAccount.  Ensure user has atleast iam.serviceAccounts.get permissions ")
		return nil, fmt.Errorf("Could not Read serviceAccount %v", err)
	}
	glog.V(2).Infof("     Existing project level metadata permissions ---> %v", rr.Permissions)

	return ret, nil
}

func checkNetworkConnectivity(ctx context.Context, destIP string, port int) (err error) {
	glog.V(2).Infof("     Checking network connectivity using Dial: [%s:%d]", destIP, port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", destIP+":"+strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("Could not resolve TCP Addr %v", err)
	}
	_, err = net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		glog.Errorf("     Could not Dial.  Check if Firewall rules allow ort 22 connectivity to VM.   Error: [%v]", err)
		if *enableTraceRoute {
			timeout := 100
			glog.V(2).Infof("     Running traceRoute with timeout %d", timeout)
			ot := new(traceroute.TracerouteOptions)
			ot.SetTimeoutMs(timeout)
			out, err := traceroute.Traceroute(destIP, ot)
			if err == nil {
				if len(out.Hops) == 0 {
					return fmt.Errorf("TestTraceroute failed. Expected at least one hop")
				}
			} else {
				return fmt.Errorf("TestTraceroute failed due to an error: %v", err)
			}

			for _, hop := range out.Hops {
				glog.V(2).Infof("      %-3d %v (%v)  %v\n", hop.TTL, hop.HostOrAddressString(), hop.AddressString(), hop.ElapsedTime)
			}
		}
	} else {
		glog.V(2).Infof("    Network Connectivity Established ")
	}

	return nil
}

func getHostKey(host string) (ssh.PublicKey, error) {
	file, err := os.Open(*sshKnownHosts)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, errors.New(fmt.Sprintf("error parsing %q: %v", fields[2], err))
			}
			break
		}
	}

	if hostKey == nil {
		return nil, errors.New(fmt.Sprintf("no hostkey for %s", host))
	}
	return hostKey, nil
}

func verifySSHKeys(ctx context.Context, pubKeys []ssh.PublicKey) error {

	key, err := ioutil.ReadFile(*sshPrivKey)
	if err != nil {
		return fmt.Errorf("unable to read SSH private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %v", err)
	}
	verified := false
	for _, pub := range pubKeys {
		data := []byte("sign me")
		sig, err := signer.Sign(rand.Reader, data)
		if err != nil {
			return fmt.Errorf("Error signing with SSH PrivateKey: %v", err)
		}
		if err := pub.Verify(data, sig); err != nil {
			glog.V(2).Infof("Error Verifying with key: [%s] %v", ssh.FingerprintSHA256(pub), err)
		} else {
			verified = true
			glog.V(2).Infof("     Verifying with key: [%s]", ssh.FingerprintSHA256(pub))
			break
		}
	}
	if verified {
		return nil
	}
	return fmt.Errorf("Could not match ssh key to private key")
}

func checkSSH(ctx context.Context, username string, destIP string, port int, instanceID string) (err error) {
	glog.V(2).Infof("     Checking ssh connectivity to: [%s:%d]", destIP, port)

	key, err := ioutil.ReadFile(*sshPrivKey)
	if err != nil {
		return fmt.Errorf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %v", err)
	}

	hostKey, err := getHostKey("compute." + instanceID)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	sshConn, err := ssh.Dial("tcp", destIP+":"+strconv.Itoa(port), sshConfig)
	if err != nil {
		return fmt.Errorf("     Could not DialSSH .%v", err)
	}
	glog.V(2).Infof("     SSH connection successful ", string(sshConn.Conn.ServerVersion()))

	var b bytes.Buffer
	// Create a session. It is one session per command.
	session, err := sshConn.NewSession()
	if err != nil {
		return fmt.Errorf("     Could not create SSH Connection .%v", err)
	}
	session.Stdout = &b
	err = session.Run("echo \"connected as user\" $USER \" to \" `hostname`")
	glog.V(2).Infof("     Remote Command: %v", b.String())

	defer sshConn.Close()

	return nil
}

func containsInSlice(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()
	glog.V(2).Infof("========  Starting Troubleshooter ========")
	if *accessToken == "" {
		glog.Fatal("Access Token must be provided")
	}

	if *connectUserName == "" {
		user, err := user.Current()
		if err != nil {
			glog.Fatal(err)
		}
		*connectUserName = user.Username
	}
	glog.V(2).Infof("========  User %s", *connectUserName)
	usr, err := user.Current()
	if err != nil {
		glog.Fatal(err)
	}

	if *sshPub == "" {
		*sshPub = usr.HomeDir + "/.ssh/google_compute_engine.pub"
	}
	if *sshKnownHosts == "" {
		*sshKnownHosts = usr.HomeDir + "/.ssh/google_compute_known_hosts"
	}
	if *sshPrivKey == "" {
		*sshPrivKey = usr.HomeDir + "/.ssh/google_compute_engine"
	}

	token := &oauth2.Token{
		TokenType:   "Bearer",
		AccessToken: *accessToken,
	}
	tokenSource := oauth2.StaticTokenSource(token)

	ctx := context.Background()
	user, err := getUser(ctx, tokenSource)
	if err != nil {
		glog.Error(err)
		os.Exit(-1)
	}
	glog.V(2).Infof("    Running tests for [%s]", user.Email)
	cresp, err := getInstance(ctx, tokenSource, *instance, *projectID, *zone)
	if err != nil {
		glog.Error(err)
		os.Exit(-1)
	}
	if cresp.ExternalIP != "" {
		glog.V(2).Infof("    VM Has External IP [%s], starting networking connectivity tests", cresp.ExternalIP)
		err := checkNetworkConnectivity(ctx, cresp.ExternalIP, *port)
		if err != nil {
			glog.Error(err)
			os.Exit(-1)
		}
	} else {
		glog.V(2).Infof("    VM Has no External IP.  Checking IAP Tunnel permissions")
	}
	_, err = getProject(ctx, tokenSource, *projectID)
	if err != nil {
		glog.Fatal(err)
	}

	_, err = getServiceAccount(ctx, tokenSource, *projectID, cresp.ServiceAccount)
	if err != nil {
		glog.Error(err)
		os.Exit(-1)
	}

	if *verifyIAPTunnel {
		_, err = getIAP(ctx, tokenSource, *projectID, *zone, cresp.InstanceID)
		if err != nil {
			glog.Error(err)
			os.Exit(-1)
		}
	}

	err = verifySSHKeys(ctx, cresp.SSHPubKeys)
	if err != nil {
		glog.Error(err)
		os.Exit(-1)
	} else {
		glog.V(2).Infof("    Local SSH Key Verified match to Project/Instance SSH Public Key")
	}

	if !*verifyIAPTunnel && *noverifySSH {
		err = checkSSH(ctx, *connectUserName, cresp.ExternalIP, *port, cresp.InstanceID)
		if err != nil {
			glog.Error(err)
			os.Exit(-1)
		}
	}

}
