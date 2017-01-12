package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"time"

	"os"

	_ "crypto/sha256"

	"github.com/Sirupsen/logrus"
	bugsnag "github.com/bugsnag/bugsnag-go"
	"k8s.io/client-go/kubernetes"
	k8serrors "k8s.io/client-go/pkg/api/errors"
	"k8s.io/client-go/pkg/api/v1"
	metav1 "k8s.io/client-go/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// Maximum number of retries of node status update.
	updateNodeStatusMaxRetries int = 3
)

type bgpPeer struct {
	PeerIP   string
	PeerType string
	State    string
	Since    string
	BGPState string
	Info     string
}

var (
	kubeConfig = flag.String("kubeconfig", "", "path to kubeconfig for local usage")
	printUsage = flag.Bool("help", false, "print usage")

	client *kubernetes.Clientset

	appEnv = getAppEnv()
)

// Check for Word_<IP> where every octate is seperated by "_", regardless of IP protocols
// Example match: "Mesh_192_168_56_101" or "Mesh_fd80_24e2_f998_72d7__2"
var bgpPeerRegex = regexp.MustCompile(`^(Global|Node|Mesh)_(.+)$`)

// Mapping the BIRD/GoBGP type extracted from the peer name to the display type.
var bgpTypeMap = map[string]string{
	"Global": "global",
	"Mesh":   "node-to-node mesh",
	"Node":   "node specific",
}

// Timeout for querying BIRD
var birdTimeOut = 2 * time.Second

// Expected BIRD protocol table columns
var birdExpectedHeadings = []string{"name", "proto", "table", "state", "since", "info"}

func getAppEnv() string {
	env := os.Getenv("ENV")
	if env == "" {
		return "development"
	}
	return env
}

func getKubernetesConfig() (*rest.Config, error) {
	if *kubeConfig == "" {
		// creates the in-cluster config
		return rest.InClusterConfig()
	}
	// creates config from file
	return clientcmd.BuildConfigFromFlags("", *kubeConfig)
}

func getKubernetesClient() *kubernetes.Clientset {
	config, err := getKubernetesConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Could not build kube config")
	}

	client = kubernetes.NewForConfigOrDie(config)
	return client
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()
	if *printUsage {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Emit logs as JSON to help splunk to parse it.
	logrus.SetFormatter(&logrus.JSONFormatter{})

	logrus.Info("calico-node-status started!")

	client = getKubernetesClient()

	bugsnag.Configure(bugsnag.Configuration{
		APIKey:              os.Getenv("BUGSNAG_API_KEY"),
		ReleaseStage:        appEnv,
		NotifyReleaseStages: []string{"production"},
	})

	// get peer status
	peers, err := getPeers()
	if err != nil {
		logrus.WithError(err).Fatal("Error getting peers")
	}
	logrus.Info(peers[0].State)
	updateNetworkingCondition(peersOk(peers))

	logrus.Info("Done.")
}

func updateNetworkingCondition(calicoIsSetup bool) error {
	nodeName := os.Getenv("NODE_NAME")

	var err error
	for i := 0; i < updateNodeStatusMaxRetries; i++ {
		// Patch could also fail, even though the chance is very slim. So we still do
		// patch in the retry loop.
		currentTime := metav1.Now()
		if calicoIsSetup {
			err = setNodeCondition(client, nodeName, v1.NodeCondition{
				Type:               v1.NodeNetworkUnavailable,
				Status:             v1.ConditionFalse,
				Reason:             "BGPPeeringEstablished",
				Message:            "Calico is setup and BGP peers are established.",
				LastTransitionTime: currentTime,
			})
		} else {
			err = setNodeCondition(client, nodeName, v1.NodeCondition{
				Type:               v1.NodeNetworkUnavailable,
				Status:             v1.ConditionTrue,
				Reason:             "BGPPeeringNotEstablished",
				Message:            "Calico has not been setup yet",
				LastTransitionTime: currentTime,
			})
		}
		if err == nil {
			return nil
		}
		if i == updateNodeStatusMaxRetries || !k8serrors.IsConflict(err) {
			logrus.Errorf("Error updating node %s: %v", nodeName, err)
			return err
		}
		logrus.Errorf("Error updating node %s, retrying: %v", nodeName, err)
	}
	return err
}

func setNodeCondition(c *kubernetes.Clientset, nodeName string, condition v1.NodeCondition) error {
	generatePatch := func(condition v1.NodeCondition) ([]byte, error) {
		raw, err := json.Marshal(&[]v1.NodeCondition{condition})
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf(`{"status":{"conditions":%s}}`, raw)), nil
	}
	condition.LastHeartbeatTime = metav1.NewTime(time.Now())
	patch, err := generatePatch(condition)
	if err != nil {
		return nil
	}
	_, err = c.Core().Nodes().PatchStatus(nodeName, patch)
	return err
}

func peersOk(peers []bgpPeer) bool {
	for _, v := range peers {
		if v.State == "Established" {
			return true
		}
	}
	return false
}

func getPeers() ([]bgpPeer, error) {
	c, err := net.Dial("unix", "/var/run/calico/bird4.ctl")
	if err != nil {
		logrus.WithError(err).Fatal("Error querying BIRD: unable to connect to BIRDv4 socket: /var/run/calico/bird4.ctl")
	}
	defer c.Close()
	_, err = c.Write([]byte("show protocols\n"))
	if err != nil {
		logrus.WithError(err).Fatal("Error executing command: unable to write to BIRD socket")
	}
	return scanBIRDPeers("4", c)
}

// taken from https://github.com/projectcalico/calicoctl/blob/f9f3c1ad93c4a28b3807b9ed049d90521e874e54/calicoctl/commands/node/status.go#L247-L309
func scanBIRDPeers(ipv string, conn net.Conn) ([]bgpPeer, error) {
	// Determine the separator to use for an IP address, based on the
	// IP version.
	ipSep := "."
	if ipv == "6" {
		ipSep = ":"
	}

	// The following is sample output from BIRD
	//
	// 	0001 BIRD 1.5.0 ready.
	// 	2002-name     proto    table    state  since       info
	// 	1002-kernel1  Kernel   master   up     2016-11-21
	//  	 device1  Device   master   up     2016-11-21
	//  	 direct1  Direct   master   up     2016-11-21
	//  	 Mesh_172_17_8_102 BGP      master   up     2016-11-21  Established
	// 	0000
	scanner := bufio.NewScanner(conn)
	peers := []bgpPeer{}

	// Set a time-out for reading from the socket connection.
	conn.SetReadDeadline(time.Now().Add(birdTimeOut))

	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		str := scanner.Text()
		logrus.Debugf("Read: %s\n", str)

		if strings.HasPrefix(str, "0000") {
			// "0000" means end of data
			break
		} else if strings.HasPrefix(str, "0001") {
			// "0001" code means BIRD is ready.
		} else if strings.HasPrefix(str, "2002") {
			// "2002" code means start of headings
			f := strings.Fields(str[5:])
			if !reflect.DeepEqual(f, birdExpectedHeadings) {
				return nil, errors.New("unknown BIRD table output format")
			}
		} else if strings.HasPrefix(str, "1002") {
			// "1002" code means first row of data.
			peer := bgpPeer{}
			if peer.unmarshalBIRD(str[5:], ipSep) {
				peers = append(peers, peer)
			}
		} else if strings.HasPrefix(str, " ") {
			// Row starting with a " " is another row of data.
			peer := bgpPeer{}
			if peer.unmarshalBIRD(str[1:], ipSep) {
				peers = append(peers, peer)
			}
		} else {
			// Format of row is unexpected.
			return nil, errors.New("unexpected output line from BIRD")
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		conn.SetReadDeadline(time.Now().Add(birdTimeOut))
	}

	return peers, scanner.Err()
}

// Unmarshal a peer from a line in the BIRD protocol output.  Returns true if
// successful, false otherwise.
func (b *bgpPeer) unmarshalBIRD(line, ipSep string) bool {
	// Split into fields.  We expect at least 6 columns:
	// 	name, proto, table, state, since and info.
	// The info column contains the BGP state plus possibly some additional
	// info (which will be columns > 6).
	//
	// Peer names will be of the format described by bgpPeerRegex.
	logrus.Debugf("Parsing line: %s", line)
	columns := strings.Fields(line)
	if len(columns) < 6 {
		logrus.Debugf("Not a valid line: fewer than 6 columns")
		return false
	}
	if columns[1] != "BGP" {
		logrus.Debugf("Not a valid line: protocol is not BGP")
		return false
	}

	// Check the name of the peer is of the correct format.  This regex
	// returns two components:
	// -  A type (Global|Node|Mesh) which we can map to a display type
	// -  An IP address (with _ separating the octets)
	sm := bgpPeerRegex.FindStringSubmatch(columns[0])
	if len(sm) != 3 {
		logrus.Debugf("Not a valid line: peer name '%s' is not correct format", columns[0])
		return false
	}
	var ok bool
	b.PeerIP = strings.Replace(sm[2], "_", ipSep, -1)
	if b.PeerType, ok = bgpTypeMap[sm[1]]; !ok {
		logrus.Debugf("Not a valid line: peer type '%s' is not recognized", sm[1])
		return false
	}

	// Store remaining columns (piecing back together the info string)
	b.State = columns[3]
	b.Since = columns[4]
	b.BGPState = columns[5]
	if len(columns) > 6 {
		b.Info = strings.Join(columns[6:], " ")
	}

	return true
}
