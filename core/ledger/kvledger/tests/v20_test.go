/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tests

import (
	"fmt"
	"testing"

	"github.com/jxu86/fabric-gm/common/ledger/testutil"
	"github.com/jxu86/fabric-gm/core/chaincode/lifecycle"
	"github.com/jxu86/fabric-gm/core/ledger/kvledger"
	"github.com/stretchr/testify/require"
)

// TestV20SampleLedger tests rebuild function with sample v2.0 ledger data generated by integration/ledger/ledger_generate_test.go
func TestV20SampleLedger(t *testing.T) {
	env := newEnv(t)
	defer env.cleanup()

	dataHelper := &v20SampleDataHelper{sampleDataVersion: "v2.0", t: t}
	env.initializer.DeployedChaincodeInfoProvider = createDeployedCCInfoProvider(dataHelper.mspIDsInChannelConfig())
	ledgerFSRoot := env.initializer.Config.RootFSPath
	require.NoError(t, testutil.Unzip("testdata/v20/sample_ledgers/ledgersData.zip", ledgerFSRoot, false))

	env.initLedgerMgmt()
	h1 := env.newTestHelperOpenLgr("testchannel", t)
	dataHelper.verify(h1)

	// rebuild and verify again
	env.closeLedgerMgmt()
	kvledger.RebuildDBs(env.initializer.Config)
	env.initLedgerMgmt()
	h1 = env.newTestHelperOpenLgr("testchannel", t)
	dataHelper.verify(h1)
}

// The generated ledger has the following blocks:
// block 0: genesis
// block 1 to 4: network setup
// block 5 to 8: marblesp chaincode instantiation
// block 9 to 12: marbles chancode instantiation
// block 13: marblesp chaincode invocation (new marble1)
// block 14 to 17: upgrade marblesp chaincode with a new collection config
// block 18 to 19: marbles chaincode invocation (new marble100 and transfer)
type v20SampleDataHelper struct {
	sampleDataVersion string
	t                 *testing.T
}

func (d *v20SampleDataHelper) verify(h *testhelper) {
	d.verifyState(h)
	d.verifyBlockAndPvtdata(h)
	d.verifyConfigHistory(h)
	d.verifyHistory(h)
}

func (d *v20SampleDataHelper) verifyState(h *testhelper) {
	h.verifyPubState("marbles", "marble100", d.marbleValue("marble100", "blue", "jerry", 35))
	h.verifyPvtState("marblesp", "collectionMarbles", "marble1", d.marbleValue("marble1", "blue", "tom", 35))
	h.verifyPvtState("marblesp", "collectionMarblePrivateDetails", "marble1", d.marbleDetail("marble1", 99))
}

func (d *v20SampleDataHelper) verifyHistory(h *testhelper) {
	expectedHistoryValue1 := []string{
		d.marbleValue("marble100", "blue", "jerry", 35),
		d.marbleValue("marble100", "blue", "tom", 35),
	}
	h.verifyHistory("marbles", "marble100", expectedHistoryValue1)
}

func (d *v20SampleDataHelper) verifyConfigHistory(h *testhelper) {
	// below block 10 should match integration/ledger/testdata/collection_configs/collections_config1.json
	h.verifyMostRecentCollectionConfigBelow(10, "marblesp",
		&expectedCollConfInfo{8, d.marbleCollConf1("marbelsp")})

	// below block 18 should match integration/ledger/testdata/collection_configs/collections_config2.json
	h.verifyMostRecentCollectionConfigBelow(18, "marblesp",
		&expectedCollConfInfo{17, d.marbleCollConf2("marbelsp")})
}

func (d *v20SampleDataHelper) verifyBlockAndPvtdata(h *testhelper) {
	h.verifyBlockAndPvtData(8, nil, func(r *retrievedBlockAndPvtdata) {
		r.hasNumTx(1)
		r.hasNoPvtdata()
	})

	h.verifyBlockAndPvtData(13, nil, func(r *retrievedBlockAndPvtdata) {
		r.hasNumTx(1)
		r.pvtdataShouldContain(0, "marblesp", "collectionMarbles", "marble1", d.marbleValue("marble1", "blue", "tom", 35))
		r.pvtdataShouldContain(0, "marblesp", "collectionMarblePrivateDetails", "marble1", d.marbleDetail("marble1", 99))
	})
}

func (d *v20SampleDataHelper) marbleValue(name, color, owner string, size int) string {
	return fmt.Sprintf(`{"docType":"marble","name":"%s","color":"%s","size":%d,"owner":"%s"}`, name, color, size, owner)
}

func (d *v20SampleDataHelper) marbleDetail(name string, price int) string {
	return fmt.Sprintf(`{"docType":"marblePrivateDetails","name":"%s","price":%d}`, name, price)
}

func (d *v20SampleDataHelper) mspIDsInChannelConfig() []string {
	return []string{"Org1MSP", "Org2MSP", "Org2MSP"}
}

// match integration/ledger/testdata/collection_configs/collections_config1.json
func (d *v20SampleDataHelper) marbleCollConf1(ccName string) []*collConf {
	collConfigs := make([]*collConf, 0)
	collConfigs = append(collConfigs, &collConf{name: "collectionMarbles", btl: 1000000, members: []string{"Org1MSP", "Org2MSP"}})
	collConfigs = append(collConfigs, &collConf{name: "collectionMarblePrivateDetails", btl: 1000000, members: []string{"Org2MSP", "Org3MSP"}})
	for _, mspID := range d.mspIDsInChannelConfig() {
		collConfigs = append(collConfigs, &collConf{name: lifecycle.ImplicitCollectionNameForOrg(mspID), btl: 0, members: []string{mspID}})
	}
	return collConfigs
}

// match integration/ledger/testdata/collection_configs/collections_config2.json
func (d *v20SampleDataHelper) marbleCollConf2(ccName string) []*collConf {
	collConfigs := make([]*collConf, 0)
	collConfigs = append(collConfigs, &collConf{name: "collectionMarbles", btl: 1000000, members: []string{"Org2MSP", "Org3MSP"}})
	collConfigs = append(collConfigs, &collConf{name: "collectionMarblePrivateDetails", btl: 1000000, members: []string{"Org1MSP", "Org2MSP", "Org3MSP"}})
	for _, mspID := range d.mspIDsInChannelConfig() {
		collConfigs = append(collConfigs, &collConf{name: lifecycle.ImplicitCollectionNameForOrg(mspID), btl: 0, members: []string{mspID}})
	}
	return collConfigs
}
