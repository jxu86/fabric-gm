// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/jxu86/fabric-gm/common/channelconfig"
)

type Application struct {
	APIPolicyMapperStub        func() channelconfig.PolicyMapper
	aPIPolicyMapperMutex       sync.RWMutex
	aPIPolicyMapperArgsForCall []struct {
	}
	aPIPolicyMapperReturns struct {
		result1 channelconfig.PolicyMapper
	}
	aPIPolicyMapperReturnsOnCall map[int]struct {
		result1 channelconfig.PolicyMapper
	}
	CapabilitiesStub        func() channelconfig.ApplicationCapabilities
	capabilitiesMutex       sync.RWMutex
	capabilitiesArgsForCall []struct {
	}
	capabilitiesReturns struct {
		result1 channelconfig.ApplicationCapabilities
	}
	capabilitiesReturnsOnCall map[int]struct {
		result1 channelconfig.ApplicationCapabilities
	}
	OrganizationsStub        func() map[string]channelconfig.ApplicationOrg
	organizationsMutex       sync.RWMutex
	organizationsArgsForCall []struct {
	}
	organizationsReturns struct {
		result1 map[string]channelconfig.ApplicationOrg
	}
	organizationsReturnsOnCall map[int]struct {
		result1 map[string]channelconfig.ApplicationOrg
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Application) APIPolicyMapper() channelconfig.PolicyMapper {
	fake.aPIPolicyMapperMutex.Lock()
	ret, specificReturn := fake.aPIPolicyMapperReturnsOnCall[len(fake.aPIPolicyMapperArgsForCall)]
	fake.aPIPolicyMapperArgsForCall = append(fake.aPIPolicyMapperArgsForCall, struct {
	}{})
	fake.recordInvocation("APIPolicyMapper", []interface{}{})
	fake.aPIPolicyMapperMutex.Unlock()
	if fake.APIPolicyMapperStub != nil {
		return fake.APIPolicyMapperStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.aPIPolicyMapperReturns
	return fakeReturns.result1
}

func (fake *Application) APIPolicyMapperCallCount() int {
	fake.aPIPolicyMapperMutex.RLock()
	defer fake.aPIPolicyMapperMutex.RUnlock()
	return len(fake.aPIPolicyMapperArgsForCall)
}

func (fake *Application) APIPolicyMapperCalls(stub func() channelconfig.PolicyMapper) {
	fake.aPIPolicyMapperMutex.Lock()
	defer fake.aPIPolicyMapperMutex.Unlock()
	fake.APIPolicyMapperStub = stub
}

func (fake *Application) APIPolicyMapperReturns(result1 channelconfig.PolicyMapper) {
	fake.aPIPolicyMapperMutex.Lock()
	defer fake.aPIPolicyMapperMutex.Unlock()
	fake.APIPolicyMapperStub = nil
	fake.aPIPolicyMapperReturns = struct {
		result1 channelconfig.PolicyMapper
	}{result1}
}

func (fake *Application) APIPolicyMapperReturnsOnCall(i int, result1 channelconfig.PolicyMapper) {
	fake.aPIPolicyMapperMutex.Lock()
	defer fake.aPIPolicyMapperMutex.Unlock()
	fake.APIPolicyMapperStub = nil
	if fake.aPIPolicyMapperReturnsOnCall == nil {
		fake.aPIPolicyMapperReturnsOnCall = make(map[int]struct {
			result1 channelconfig.PolicyMapper
		})
	}
	fake.aPIPolicyMapperReturnsOnCall[i] = struct {
		result1 channelconfig.PolicyMapper
	}{result1}
}

func (fake *Application) Capabilities() channelconfig.ApplicationCapabilities {
	fake.capabilitiesMutex.Lock()
	ret, specificReturn := fake.capabilitiesReturnsOnCall[len(fake.capabilitiesArgsForCall)]
	fake.capabilitiesArgsForCall = append(fake.capabilitiesArgsForCall, struct {
	}{})
	fake.recordInvocation("Capabilities", []interface{}{})
	fake.capabilitiesMutex.Unlock()
	if fake.CapabilitiesStub != nil {
		return fake.CapabilitiesStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.capabilitiesReturns
	return fakeReturns.result1
}

func (fake *Application) CapabilitiesCallCount() int {
	fake.capabilitiesMutex.RLock()
	defer fake.capabilitiesMutex.RUnlock()
	return len(fake.capabilitiesArgsForCall)
}

func (fake *Application) CapabilitiesCalls(stub func() channelconfig.ApplicationCapabilities) {
	fake.capabilitiesMutex.Lock()
	defer fake.capabilitiesMutex.Unlock()
	fake.CapabilitiesStub = stub
}

func (fake *Application) CapabilitiesReturns(result1 channelconfig.ApplicationCapabilities) {
	fake.capabilitiesMutex.Lock()
	defer fake.capabilitiesMutex.Unlock()
	fake.CapabilitiesStub = nil
	fake.capabilitiesReturns = struct {
		result1 channelconfig.ApplicationCapabilities
	}{result1}
}

func (fake *Application) CapabilitiesReturnsOnCall(i int, result1 channelconfig.ApplicationCapabilities) {
	fake.capabilitiesMutex.Lock()
	defer fake.capabilitiesMutex.Unlock()
	fake.CapabilitiesStub = nil
	if fake.capabilitiesReturnsOnCall == nil {
		fake.capabilitiesReturnsOnCall = make(map[int]struct {
			result1 channelconfig.ApplicationCapabilities
		})
	}
	fake.capabilitiesReturnsOnCall[i] = struct {
		result1 channelconfig.ApplicationCapabilities
	}{result1}
}

func (fake *Application) Organizations() map[string]channelconfig.ApplicationOrg {
	fake.organizationsMutex.Lock()
	ret, specificReturn := fake.organizationsReturnsOnCall[len(fake.organizationsArgsForCall)]
	fake.organizationsArgsForCall = append(fake.organizationsArgsForCall, struct {
	}{})
	fake.recordInvocation("Organizations", []interface{}{})
	fake.organizationsMutex.Unlock()
	if fake.OrganizationsStub != nil {
		return fake.OrganizationsStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.organizationsReturns
	return fakeReturns.result1
}

func (fake *Application) OrganizationsCallCount() int {
	fake.organizationsMutex.RLock()
	defer fake.organizationsMutex.RUnlock()
	return len(fake.organizationsArgsForCall)
}

func (fake *Application) OrganizationsCalls(stub func() map[string]channelconfig.ApplicationOrg) {
	fake.organizationsMutex.Lock()
	defer fake.organizationsMutex.Unlock()
	fake.OrganizationsStub = stub
}

func (fake *Application) OrganizationsReturns(result1 map[string]channelconfig.ApplicationOrg) {
	fake.organizationsMutex.Lock()
	defer fake.organizationsMutex.Unlock()
	fake.OrganizationsStub = nil
	fake.organizationsReturns = struct {
		result1 map[string]channelconfig.ApplicationOrg
	}{result1}
}

func (fake *Application) OrganizationsReturnsOnCall(i int, result1 map[string]channelconfig.ApplicationOrg) {
	fake.organizationsMutex.Lock()
	defer fake.organizationsMutex.Unlock()
	fake.OrganizationsStub = nil
	if fake.organizationsReturnsOnCall == nil {
		fake.organizationsReturnsOnCall = make(map[int]struct {
			result1 map[string]channelconfig.ApplicationOrg
		})
	}
	fake.organizationsReturnsOnCall[i] = struct {
		result1 map[string]channelconfig.ApplicationOrg
	}{result1}
}

func (fake *Application) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.aPIPolicyMapperMutex.RLock()
	defer fake.aPIPolicyMapperMutex.RUnlock()
	fake.capabilitiesMutex.RLock()
	defer fake.capabilitiesMutex.RUnlock()
	fake.organizationsMutex.RLock()
	defer fake.organizationsMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Application) recordInvocation(key string, args []interface{}) {
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
