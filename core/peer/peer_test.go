/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/jxu86/fabric-gm/bccsp/sw"
	configtxtest "github.com/jxu86/fabric-gm/common/configtx/test"
	"github.com/jxu86/fabric-gm/common/metrics/disabled"
	"github.com/jxu86/fabric-gm/core/committer/txvalidator/plugin"
	"github.com/jxu86/fabric-gm/core/deliverservice"
	validation "github.com/jxu86/fabric-gm/core/handlers/validation/api"
	"github.com/jxu86/fabric-gm/core/ledger"
	"github.com/jxu86/fabric-gm/core/ledger/ledgermgmt"
	"github.com/jxu86/fabric-gm/core/ledger/ledgermgmt/ledgermgmttest"
	"github.com/jxu86/fabric-gm/core/ledger/mock"
	ledgermocks "github.com/jxu86/fabric-gm/core/ledger/mock"
	"github.com/jxu86/fabric-gm/core/transientstore"
	"github.com/jxu86/fabric-gm/gossip/gossip"
	gossipmetrics "github.com/jxu86/fabric-gm/gossip/metrics"
	"github.com/jxu86/fabric-gm/gossip/privdata"
	"github.com/jxu86/fabric-gm/gossip/service"
	gossipservice "github.com/jxu86/fabric-gm/gossip/service"
	peergossip "github.com/jxu86/fabric-gm/internal/peer/gossip"
	"github.com/jxu86/fabric-gm/internal/peer/gossip/mocks"
	"github.com/jxu86/fabric-gm/internal/pkg/comm"
	"github.com/jxu86/fabric-gm/msp/mgmt"
	msptesttools "github.com/jxu86/fabric-gm/msp/mgmt/testtools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	msptesttools.LoadMSPSetupForTesting()
	rc := m.Run()
	os.Exit(rc)
}

func NewTestPeer(t *testing.T) (*Peer, func()) {
	tempdir, err := ioutil.TempDir("", "peer-test")
	require.NoError(t, err, "failed to create temporary directory")

	// Initialize gossip service
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	signer := mgmt.GetLocalSigningIdentityOrPanic(cryptoProvider)

	messageCryptoService := peergossip.NewMCS(&mocks.ChannelPolicyManagerGetter{}, signer, mgmt.NewDeserializersManager(cryptoProvider), cryptoProvider)
	secAdv := peergossip.NewSecurityAdvisor(mgmt.NewDeserializersManager(cryptoProvider))
	defaultSecureDialOpts := func() []grpc.DialOption { return []grpc.DialOption{grpc.WithInsecure()} }
	var defaultDeliverClientDialOpts []grpc.DialOption
	defaultDeliverClientDialOpts = append(
		defaultDeliverClientDialOpts,
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(comm.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(comm.MaxSendMsgSize),
		),
	)
	defaultDeliverClientDialOpts = append(
		defaultDeliverClientDialOpts,
		comm.ClientKeepaliveOptions(comm.DefaultKeepaliveOptions)...,
	)
	gossipConfig, err := gossip.GlobalConfig("localhost:0", nil)
	require.NoError(t, err)

	gossipService, err := gossipservice.New(
		signer,
		gossipmetrics.NewGossipMetrics(&disabled.Provider{}),
		"localhost:0",
		grpc.NewServer(),
		messageCryptoService,
		secAdv,
		defaultSecureDialOpts,
		nil,
		nil,
		gossipConfig,
		&service.ServiceConfig{},
		&privdata.PrivdataConfig{},
		&deliverservice.DeliverServiceConfig{
			ReConnectBackoffThreshold:   deliverservice.DefaultReConnectBackoffThreshold,
			ReconnectTotalTimeThreshold: deliverservice.DefaultReConnectTotalTimeThreshold,
		},
	)
	require.NoError(t, err, "failed to create gossip service")

	ledgerMgr, err := constructLedgerMgrWithTestDefaults(filepath.Join(tempdir, "ledgersData"))
	require.NoError(t, err, "failed to create ledger manager")

	assert.NoError(t, err)
	transientStoreProvider, err := transientstore.NewStoreProvider(
		filepath.Join(tempdir, "transientstore"),
	)
	assert.NoError(t, err)
	peerInstance := &Peer{
		GossipService:  gossipService,
		StoreProvider:  transientStoreProvider,
		LedgerMgr:      ledgerMgr,
		CryptoProvider: cryptoProvider,
	}

	cleanup := func() {
		ledgerMgr.Close()
		os.RemoveAll(tempdir)
	}
	return peerInstance, cleanup
}

func TestInitialize(t *testing.T) {
	peerInstance, cleanup := NewTestPeer(t)
	defer cleanup()

	org1CA, err := ioutil.ReadFile(filepath.Join("testdata", "Org1-cert.pem"))
	require.NoError(t, err)
	org1Server1Key, err := ioutil.ReadFile(filepath.Join("testdata", "Org1-server1-key.pem"))
	require.NoError(t, err)
	org1Server1Cert, err := ioutil.ReadFile(filepath.Join("testdata", "Org1-server1-cert.pem"))
	require.NoError(t, err)
	serverConfig := comm.ServerConfig{
		SecOpts: comm.SecureOptions{
			UseTLS:            true,
			Certificate:       org1Server1Cert,
			Key:               org1Server1Key,
			ServerRootCAs:     [][]byte{org1CA},
			RequireClientCert: true,
		},
	}

	server, err := comm.NewGRPCServer("localhost:0", serverConfig)
	if err != nil {
		t.Fatalf("NewGRPCServer failed with error [%s]", err)
		return
	}

	peerInstance.Initialize(
		nil,
		server,
		plugin.MapBasedMapper(map[string]validation.PluginFactory{}),
		&ledgermocks.DeployedChaincodeInfoProvider{},
		nil,
		nil,
		runtime.NumCPU(),
	)
	assert.Equal(t, peerInstance.server, server)
}

func TestCreateChannel(t *testing.T) {
	peerInstance, cleanup := NewTestPeer(t)
	defer cleanup()

	var initArg string
	peerInstance.Initialize(
		func(cid string) { initArg = cid },
		nil,
		plugin.MapBasedMapper(map[string]validation.PluginFactory{}),
		&ledgermocks.DeployedChaincodeInfoProvider{},
		nil,
		nil,
		runtime.NumCPU(),
	)

	testChannelID := fmt.Sprintf("mytestchannelid-%d", rand.Int())
	block, err := configtxtest.MakeGenesisBlock(testChannelID)
	if err != nil {
		fmt.Printf("Failed to create a config block, err %s\n", err)
		t.FailNow()
	}

	err = peerInstance.CreateChannel(testChannelID, block, &mock.DeployedChaincodeInfoProvider{}, nil, nil)
	if err != nil {
		t.Fatalf("failed to create chain %s", err)
	}

	assert.Equal(t, testChannelID, initArg)

	// Correct ledger
	ledger := peerInstance.GetLedger(testChannelID)
	if ledger == nil {
		t.Fatalf("failed to get correct ledger")
	}

	// Get config block from ledger
	block, err = ConfigBlockFromLedger(ledger)
	assert.NoError(t, err, "Failed to get config block from ledger")
	assert.NotNil(t, block, "Config block should not be nil")
	assert.Equal(t, uint64(0), block.Header.Number, "config block should have been block 0")

	// Bad ledger
	ledger = peerInstance.GetLedger("BogusChain")
	if ledger != nil {
		t.Fatalf("got a bogus ledger")
	}

	// Correct PolicyManager
	pmgr := peerInstance.GetPolicyManager(testChannelID)
	if pmgr == nil {
		t.Fatal("failed to get PolicyManager")
	}

	// Bad PolicyManager
	pmgr = peerInstance.GetPolicyManager("BogusChain")
	if pmgr != nil {
		t.Fatal("got a bogus PolicyManager")
	}

	channels := peerInstance.GetChannelsInfo()
	if len(channels) != 1 {
		t.Fatalf("incorrect number of channels")
	}
}

func TestDeliverSupportManager(t *testing.T) {
	peerInstance, cleanup := NewTestPeer(t)
	defer cleanup()

	manager := &DeliverChainManager{Peer: peerInstance}

	chainSupport := manager.GetChain("fake")
	assert.Nil(t, chainSupport, "chain support should be nil")

	peerInstance.channels = map[string]*Channel{"testchain": {}}
	chainSupport = manager.GetChain("testchain")
	assert.NotNil(t, chainSupport, "chain support should not be nil")
}

func constructLedgerMgrWithTestDefaults(ledgersDataDir string) (*ledgermgmt.LedgerMgr, error) {
	ledgerInitializer := ledgermgmttest.NewInitializer(ledgersDataDir)

	ledgerInitializer.CustomTxProcessors = map[common.HeaderType]ledger.CustomTxProcessor{
		common.HeaderType_CONFIG: &ConfigTxProcessor{},
	}
	ledgerInitializer.Config.HistoryDBConfig = &ledger.HistoryDBConfig{
		Enabled: true,
	}
	return ledgermgmt.NewLedgerMgr(ledgerInitializer), nil
}

// SetServer sets the gRPC server for the peer.
// It should only be used in peer/pkg_test.
func (p *Peer) SetServer(server *comm.GRPCServer) {
	p.server = server
}
