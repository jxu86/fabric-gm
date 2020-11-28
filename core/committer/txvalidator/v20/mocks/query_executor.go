// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import coreledger "github.com/jxu86/fabric-gm/core/ledger"
import ledger "github.com/jxu86/fabric-gm/common/ledger"
import mock "github.com/stretchr/testify/mock"

// QueryExecutor is an autogenerated mock type for the QueryExecutor type
type QueryExecutor struct {
	mock.Mock
}

// Done provides a mock function with given fields:
func (_m *QueryExecutor) Done() {
	_m.Called()
}

// ExecuteQuery provides a mock function with given fields: namespace, query
func (_m *QueryExecutor) ExecuteQuery(namespace string, query string) (ledger.ResultsIterator, error) {
	ret := _m.Called(namespace, query)

	var r0 ledger.ResultsIterator
	if rf, ok := ret.Get(0).(func(string, string) ledger.ResultsIterator); ok {
		r0 = rf(namespace, query)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ledger.ResultsIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(namespace, query)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ExecuteQueryOnPrivateData provides a mock function with given fields: namespace, collection, query
func (_m *QueryExecutor) ExecuteQueryOnPrivateData(namespace string, collection string, query string) (ledger.ResultsIterator, error) {
	ret := _m.Called(namespace, collection, query)

	var r0 ledger.ResultsIterator
	if rf, ok := ret.Get(0).(func(string, string, string) ledger.ResultsIterator); ok {
		r0 = rf(namespace, collection, query)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ledger.ResultsIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(namespace, collection, query)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ExecuteQueryWithPagination provides a mock function with given fields: namespace, query, bookmark, pageSize
func (_m *QueryExecutor) ExecuteQueryWithPagination(namespace string, query string, bookmark string, pageSize int32) (coreledger.QueryResultsIterator, error) {
	ret := _m.Called(namespace, query, bookmark, pageSize)

	var r0 coreledger.QueryResultsIterator
	if rf, ok := ret.Get(0).(func(string, string, string, int32) coreledger.QueryResultsIterator); ok {
		r0 = rf(namespace, query, bookmark, pageSize)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(coreledger.QueryResultsIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string, int32) error); ok {
		r1 = rf(namespace, query, bookmark, pageSize)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPrivateData provides a mock function with given fields: namespace, collection, key
func (_m *QueryExecutor) GetPrivateData(namespace string, collection string, key string) ([]byte, error) {
	ret := _m.Called(namespace, collection, key)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string, string, string) []byte); ok {
		r0 = rf(namespace, collection, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(namespace, collection, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPrivateDataHash provides a mock function with given fields: namespace, collection, key
func (_m *QueryExecutor) GetPrivateDataHash(namespace string, collection string, key string) ([]byte, error) {
	ret := _m.Called(namespace, collection, key)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string, string, string) []byte); ok {
		r0 = rf(namespace, collection, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(namespace, collection, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPrivateDataMetadata provides a mock function with given fields: namespace, collection, key
func (_m *QueryExecutor) GetPrivateDataMetadata(namespace string, collection string, key string) (map[string][]byte, error) {
	ret := _m.Called(namespace, collection, key)

	var r0 map[string][]byte
	if rf, ok := ret.Get(0).(func(string, string, string) map[string][]byte); ok {
		r0 = rf(namespace, collection, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string][]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(namespace, collection, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPrivateDataMetadataByHash provides a mock function with given fields: namespace, collection, keyhash
func (_m *QueryExecutor) GetPrivateDataMetadataByHash(namespace string, collection string, keyhash []byte) (map[string][]byte, error) {
	ret := _m.Called(namespace, collection, keyhash)

	var r0 map[string][]byte
	if rf, ok := ret.Get(0).(func(string, string, []byte) map[string][]byte); ok {
		r0 = rf(namespace, collection, keyhash)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string][]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, []byte) error); ok {
		r1 = rf(namespace, collection, keyhash)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPrivateDataMultipleKeys provides a mock function with given fields: namespace, collection, keys
func (_m *QueryExecutor) GetPrivateDataMultipleKeys(namespace string, collection string, keys []string) ([][]byte, error) {
	ret := _m.Called(namespace, collection, keys)

	var r0 [][]byte
	if rf, ok := ret.Get(0).(func(string, string, []string) [][]byte); ok {
		r0 = rf(namespace, collection, keys)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([][]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, []string) error); ok {
		r1 = rf(namespace, collection, keys)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPrivateDataRangeScanIterator provides a mock function with given fields: namespace, collection, startKey, endKey
func (_m *QueryExecutor) GetPrivateDataRangeScanIterator(namespace string, collection string, startKey string, endKey string) (ledger.ResultsIterator, error) {
	ret := _m.Called(namespace, collection, startKey, endKey)

	var r0 ledger.ResultsIterator
	if rf, ok := ret.Get(0).(func(string, string, string, string) ledger.ResultsIterator); ok {
		r0 = rf(namespace, collection, startKey, endKey)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ledger.ResultsIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string, string) error); ok {
		r1 = rf(namespace, collection, startKey, endKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetState provides a mock function with given fields: namespace, key
func (_m *QueryExecutor) GetState(namespace string, key string) ([]byte, error) {
	ret := _m.Called(namespace, key)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string, string) []byte); ok {
		r0 = rf(namespace, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(namespace, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetStateMetadata provides a mock function with given fields: namespace, key
func (_m *QueryExecutor) GetStateMetadata(namespace string, key string) (map[string][]byte, error) {
	ret := _m.Called(namespace, key)

	var r0 map[string][]byte
	if rf, ok := ret.Get(0).(func(string, string) map[string][]byte); ok {
		r0 = rf(namespace, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string][]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(namespace, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetStateMultipleKeys provides a mock function with given fields: namespace, keys
func (_m *QueryExecutor) GetStateMultipleKeys(namespace string, keys []string) ([][]byte, error) {
	ret := _m.Called(namespace, keys)

	var r0 [][]byte
	if rf, ok := ret.Get(0).(func(string, []string) [][]byte); ok {
		r0 = rf(namespace, keys)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([][]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, []string) error); ok {
		r1 = rf(namespace, keys)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetStateRangeScanIterator provides a mock function with given fields: namespace, startKey, endKey
func (_m *QueryExecutor) GetStateRangeScanIterator(namespace string, startKey string, endKey string) (ledger.ResultsIterator, error) {
	ret := _m.Called(namespace, startKey, endKey)

	var r0 ledger.ResultsIterator
	if rf, ok := ret.Get(0).(func(string, string, string) ledger.ResultsIterator); ok {
		r0 = rf(namespace, startKey, endKey)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ledger.ResultsIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(namespace, startKey, endKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetStateRangeScanIteratorWithPagination provides a mock function with given fields: namespace, startKey, endKey, pageSize
func (_m *QueryExecutor) GetStateRangeScanIteratorWithPagination(namespace string, startKey string, endKey string, pageSize int32) (coreledger.QueryResultsIterator, error) {
	ret := _m.Called(namespace, startKey, endKey, pageSize)

	var r0 coreledger.QueryResultsIterator
	if rf, ok := ret.Get(0).(func(string, string, string, int32) coreledger.QueryResultsIterator); ok {
		r0 = rf(namespace, startKey, endKey, pageSize)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(coreledger.QueryResultsIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string, int32) error); ok {
		r1 = rf(namespace, startKey, endKey, pageSize)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
