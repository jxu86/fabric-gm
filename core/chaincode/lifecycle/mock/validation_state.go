// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	validation "github.com/jxu86/fabric-gm/core/handlers/validation/api/state"
)

type ValidationState struct {
	DoneStub        func()
	doneMutex       sync.RWMutex
	doneArgsForCall []struct {
	}
	GetPrivateDataMetadataByHashStub        func(string, string, []byte) (map[string][]byte, error)
	getPrivateDataMetadataByHashMutex       sync.RWMutex
	getPrivateDataMetadataByHashArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 []byte
	}
	getPrivateDataMetadataByHashReturns struct {
		result1 map[string][]byte
		result2 error
	}
	getPrivateDataMetadataByHashReturnsOnCall map[int]struct {
		result1 map[string][]byte
		result2 error
	}
	GetStateMetadataStub        func(string, string) (map[string][]byte, error)
	getStateMetadataMutex       sync.RWMutex
	getStateMetadataArgsForCall []struct {
		arg1 string
		arg2 string
	}
	getStateMetadataReturns struct {
		result1 map[string][]byte
		result2 error
	}
	getStateMetadataReturnsOnCall map[int]struct {
		result1 map[string][]byte
		result2 error
	}
	GetStateMultipleKeysStub        func(string, []string) ([][]byte, error)
	getStateMultipleKeysMutex       sync.RWMutex
	getStateMultipleKeysArgsForCall []struct {
		arg1 string
		arg2 []string
	}
	getStateMultipleKeysReturns struct {
		result1 [][]byte
		result2 error
	}
	getStateMultipleKeysReturnsOnCall map[int]struct {
		result1 [][]byte
		result2 error
	}
	GetStateRangeScanIteratorStub        func(string, string, string) (validation.ResultsIterator, error)
	getStateRangeScanIteratorMutex       sync.RWMutex
	getStateRangeScanIteratorArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 string
	}
	getStateRangeScanIteratorReturns struct {
		result1 validation.ResultsIterator
		result2 error
	}
	getStateRangeScanIteratorReturnsOnCall map[int]struct {
		result1 validation.ResultsIterator
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ValidationState) Done() {
	fake.doneMutex.Lock()
	fake.doneArgsForCall = append(fake.doneArgsForCall, struct {
	}{})
	fake.recordInvocation("Done", []interface{}{})
	fake.doneMutex.Unlock()
	if fake.DoneStub != nil {
		fake.DoneStub()
	}
}

func (fake *ValidationState) DoneCallCount() int {
	fake.doneMutex.RLock()
	defer fake.doneMutex.RUnlock()
	return len(fake.doneArgsForCall)
}

func (fake *ValidationState) DoneCalls(stub func()) {
	fake.doneMutex.Lock()
	defer fake.doneMutex.Unlock()
	fake.DoneStub = stub
}

func (fake *ValidationState) GetPrivateDataMetadataByHash(arg1 string, arg2 string, arg3 []byte) (map[string][]byte, error) {
	var arg3Copy []byte
	if arg3 != nil {
		arg3Copy = make([]byte, len(arg3))
		copy(arg3Copy, arg3)
	}
	fake.getPrivateDataMetadataByHashMutex.Lock()
	ret, specificReturn := fake.getPrivateDataMetadataByHashReturnsOnCall[len(fake.getPrivateDataMetadataByHashArgsForCall)]
	fake.getPrivateDataMetadataByHashArgsForCall = append(fake.getPrivateDataMetadataByHashArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 []byte
	}{arg1, arg2, arg3Copy})
	fake.recordInvocation("GetPrivateDataMetadataByHash", []interface{}{arg1, arg2, arg3Copy})
	fake.getPrivateDataMetadataByHashMutex.Unlock()
	if fake.GetPrivateDataMetadataByHashStub != nil {
		return fake.GetPrivateDataMetadataByHashStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getPrivateDataMetadataByHashReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *ValidationState) GetPrivateDataMetadataByHashCallCount() int {
	fake.getPrivateDataMetadataByHashMutex.RLock()
	defer fake.getPrivateDataMetadataByHashMutex.RUnlock()
	return len(fake.getPrivateDataMetadataByHashArgsForCall)
}

func (fake *ValidationState) GetPrivateDataMetadataByHashCalls(stub func(string, string, []byte) (map[string][]byte, error)) {
	fake.getPrivateDataMetadataByHashMutex.Lock()
	defer fake.getPrivateDataMetadataByHashMutex.Unlock()
	fake.GetPrivateDataMetadataByHashStub = stub
}

func (fake *ValidationState) GetPrivateDataMetadataByHashArgsForCall(i int) (string, string, []byte) {
	fake.getPrivateDataMetadataByHashMutex.RLock()
	defer fake.getPrivateDataMetadataByHashMutex.RUnlock()
	argsForCall := fake.getPrivateDataMetadataByHashArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *ValidationState) GetPrivateDataMetadataByHashReturns(result1 map[string][]byte, result2 error) {
	fake.getPrivateDataMetadataByHashMutex.Lock()
	defer fake.getPrivateDataMetadataByHashMutex.Unlock()
	fake.GetPrivateDataMetadataByHashStub = nil
	fake.getPrivateDataMetadataByHashReturns = struct {
		result1 map[string][]byte
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) GetPrivateDataMetadataByHashReturnsOnCall(i int, result1 map[string][]byte, result2 error) {
	fake.getPrivateDataMetadataByHashMutex.Lock()
	defer fake.getPrivateDataMetadataByHashMutex.Unlock()
	fake.GetPrivateDataMetadataByHashStub = nil
	if fake.getPrivateDataMetadataByHashReturnsOnCall == nil {
		fake.getPrivateDataMetadataByHashReturnsOnCall = make(map[int]struct {
			result1 map[string][]byte
			result2 error
		})
	}
	fake.getPrivateDataMetadataByHashReturnsOnCall[i] = struct {
		result1 map[string][]byte
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) GetStateMetadata(arg1 string, arg2 string) (map[string][]byte, error) {
	fake.getStateMetadataMutex.Lock()
	ret, specificReturn := fake.getStateMetadataReturnsOnCall[len(fake.getStateMetadataArgsForCall)]
	fake.getStateMetadataArgsForCall = append(fake.getStateMetadataArgsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.recordInvocation("GetStateMetadata", []interface{}{arg1, arg2})
	fake.getStateMetadataMutex.Unlock()
	if fake.GetStateMetadataStub != nil {
		return fake.GetStateMetadataStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getStateMetadataReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *ValidationState) GetStateMetadataCallCount() int {
	fake.getStateMetadataMutex.RLock()
	defer fake.getStateMetadataMutex.RUnlock()
	return len(fake.getStateMetadataArgsForCall)
}

func (fake *ValidationState) GetStateMetadataCalls(stub func(string, string) (map[string][]byte, error)) {
	fake.getStateMetadataMutex.Lock()
	defer fake.getStateMetadataMutex.Unlock()
	fake.GetStateMetadataStub = stub
}

func (fake *ValidationState) GetStateMetadataArgsForCall(i int) (string, string) {
	fake.getStateMetadataMutex.RLock()
	defer fake.getStateMetadataMutex.RUnlock()
	argsForCall := fake.getStateMetadataArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *ValidationState) GetStateMetadataReturns(result1 map[string][]byte, result2 error) {
	fake.getStateMetadataMutex.Lock()
	defer fake.getStateMetadataMutex.Unlock()
	fake.GetStateMetadataStub = nil
	fake.getStateMetadataReturns = struct {
		result1 map[string][]byte
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) GetStateMetadataReturnsOnCall(i int, result1 map[string][]byte, result2 error) {
	fake.getStateMetadataMutex.Lock()
	defer fake.getStateMetadataMutex.Unlock()
	fake.GetStateMetadataStub = nil
	if fake.getStateMetadataReturnsOnCall == nil {
		fake.getStateMetadataReturnsOnCall = make(map[int]struct {
			result1 map[string][]byte
			result2 error
		})
	}
	fake.getStateMetadataReturnsOnCall[i] = struct {
		result1 map[string][]byte
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) GetStateMultipleKeys(arg1 string, arg2 []string) ([][]byte, error) {
	var arg2Copy []string
	if arg2 != nil {
		arg2Copy = make([]string, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.getStateMultipleKeysMutex.Lock()
	ret, specificReturn := fake.getStateMultipleKeysReturnsOnCall[len(fake.getStateMultipleKeysArgsForCall)]
	fake.getStateMultipleKeysArgsForCall = append(fake.getStateMultipleKeysArgsForCall, struct {
		arg1 string
		arg2 []string
	}{arg1, arg2Copy})
	fake.recordInvocation("GetStateMultipleKeys", []interface{}{arg1, arg2Copy})
	fake.getStateMultipleKeysMutex.Unlock()
	if fake.GetStateMultipleKeysStub != nil {
		return fake.GetStateMultipleKeysStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getStateMultipleKeysReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *ValidationState) GetStateMultipleKeysCallCount() int {
	fake.getStateMultipleKeysMutex.RLock()
	defer fake.getStateMultipleKeysMutex.RUnlock()
	return len(fake.getStateMultipleKeysArgsForCall)
}

func (fake *ValidationState) GetStateMultipleKeysCalls(stub func(string, []string) ([][]byte, error)) {
	fake.getStateMultipleKeysMutex.Lock()
	defer fake.getStateMultipleKeysMutex.Unlock()
	fake.GetStateMultipleKeysStub = stub
}

func (fake *ValidationState) GetStateMultipleKeysArgsForCall(i int) (string, []string) {
	fake.getStateMultipleKeysMutex.RLock()
	defer fake.getStateMultipleKeysMutex.RUnlock()
	argsForCall := fake.getStateMultipleKeysArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *ValidationState) GetStateMultipleKeysReturns(result1 [][]byte, result2 error) {
	fake.getStateMultipleKeysMutex.Lock()
	defer fake.getStateMultipleKeysMutex.Unlock()
	fake.GetStateMultipleKeysStub = nil
	fake.getStateMultipleKeysReturns = struct {
		result1 [][]byte
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) GetStateMultipleKeysReturnsOnCall(i int, result1 [][]byte, result2 error) {
	fake.getStateMultipleKeysMutex.Lock()
	defer fake.getStateMultipleKeysMutex.Unlock()
	fake.GetStateMultipleKeysStub = nil
	if fake.getStateMultipleKeysReturnsOnCall == nil {
		fake.getStateMultipleKeysReturnsOnCall = make(map[int]struct {
			result1 [][]byte
			result2 error
		})
	}
	fake.getStateMultipleKeysReturnsOnCall[i] = struct {
		result1 [][]byte
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) GetStateRangeScanIterator(arg1 string, arg2 string, arg3 string) (validation.ResultsIterator, error) {
	fake.getStateRangeScanIteratorMutex.Lock()
	ret, specificReturn := fake.getStateRangeScanIteratorReturnsOnCall[len(fake.getStateRangeScanIteratorArgsForCall)]
	fake.getStateRangeScanIteratorArgsForCall = append(fake.getStateRangeScanIteratorArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 string
	}{arg1, arg2, arg3})
	fake.recordInvocation("GetStateRangeScanIterator", []interface{}{arg1, arg2, arg3})
	fake.getStateRangeScanIteratorMutex.Unlock()
	if fake.GetStateRangeScanIteratorStub != nil {
		return fake.GetStateRangeScanIteratorStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getStateRangeScanIteratorReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *ValidationState) GetStateRangeScanIteratorCallCount() int {
	fake.getStateRangeScanIteratorMutex.RLock()
	defer fake.getStateRangeScanIteratorMutex.RUnlock()
	return len(fake.getStateRangeScanIteratorArgsForCall)
}

func (fake *ValidationState) GetStateRangeScanIteratorCalls(stub func(string, string, string) (validation.ResultsIterator, error)) {
	fake.getStateRangeScanIteratorMutex.Lock()
	defer fake.getStateRangeScanIteratorMutex.Unlock()
	fake.GetStateRangeScanIteratorStub = stub
}

func (fake *ValidationState) GetStateRangeScanIteratorArgsForCall(i int) (string, string, string) {
	fake.getStateRangeScanIteratorMutex.RLock()
	defer fake.getStateRangeScanIteratorMutex.RUnlock()
	argsForCall := fake.getStateRangeScanIteratorArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *ValidationState) GetStateRangeScanIteratorReturns(result1 validation.ResultsIterator, result2 error) {
	fake.getStateRangeScanIteratorMutex.Lock()
	defer fake.getStateRangeScanIteratorMutex.Unlock()
	fake.GetStateRangeScanIteratorStub = nil
	fake.getStateRangeScanIteratorReturns = struct {
		result1 validation.ResultsIterator
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) GetStateRangeScanIteratorReturnsOnCall(i int, result1 validation.ResultsIterator, result2 error) {
	fake.getStateRangeScanIteratorMutex.Lock()
	defer fake.getStateRangeScanIteratorMutex.Unlock()
	fake.GetStateRangeScanIteratorStub = nil
	if fake.getStateRangeScanIteratorReturnsOnCall == nil {
		fake.getStateRangeScanIteratorReturnsOnCall = make(map[int]struct {
			result1 validation.ResultsIterator
			result2 error
		})
	}
	fake.getStateRangeScanIteratorReturnsOnCall[i] = struct {
		result1 validation.ResultsIterator
		result2 error
	}{result1, result2}
}

func (fake *ValidationState) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.doneMutex.RLock()
	defer fake.doneMutex.RUnlock()
	fake.getPrivateDataMetadataByHashMutex.RLock()
	defer fake.getPrivateDataMetadataByHashMutex.RUnlock()
	fake.getStateMetadataMutex.RLock()
	defer fake.getStateMetadataMutex.RUnlock()
	fake.getStateMultipleKeysMutex.RLock()
	defer fake.getStateMultipleKeysMutex.RUnlock()
	fake.getStateRangeScanIteratorMutex.RLock()
	defer fake.getStateRangeScanIteratorMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ValidationState) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}
