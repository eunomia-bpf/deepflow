// Code generated by tmpl; DO NOT EDIT.
// https://github.com/benbjohnson/tmpl
//
// Source: api_response.gen.go.tmpl

package aliyun

import (
	"errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	cbn "github.com/aliyun/alibaba-cloud-sdk-go/services/cbn"
	ecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	r_kvstore "github.com/aliyun/alibaba-cloud-sdk-go/services/r-kvstore"
	rds "github.com/aliyun/alibaba-cloud-sdk-go/services/rds"
	slb "github.com/aliyun/alibaba-cloud-sdk-go/services/slb"
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	simplejson "github.com/bitly/go-simplejson"
)

func (a *Aliyun) getRegionResponse(region string, request *ecs.DescribeRegionsRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := ecs.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeRegions(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Regions"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getAZResponse(region string, request *vpc.DescribeZonesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeZones(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Zones"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getVpcResponse(region string, request *vpc.DescribeVpcsRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeVpcs(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Vpcs"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getNetworkResponse(region string, request *vpc.DescribeVSwitchesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeVSwitches(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("VSwitches"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getVMResponse(region string, request *ecs.DescribeInstancesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := ecs.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeInstances(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Instances"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getVMInterfaceResponse(region string, request *ecs.DescribeNetworkInterfacesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := ecs.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeNetworkInterfaces(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("NetworkInterfaceSets"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getSecurityGroupResponse(region string, request *ecs.DescribeSecurityGroupsRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := ecs.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeSecurityGroups(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("SecurityGroups"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getSecurityGroupAttributeResponse(region string, request *ecs.DescribeSecurityGroupAttributeRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := ecs.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeSecurityGroupAttribute(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Permissions"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getRouterResponse(region string, request *vpc.DescribeRouteTableListRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeRouteTableList(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("RouterTableList"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getRouterTableResponse(region string, request *vpc.DescribeRouteEntryListRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeRouteEntryList(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("RouteEntrys"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getRedisResponse(region string, request *r_kvstore.DescribeInstancesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := r_kvstore.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeInstances(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Instances"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getRedisAttributeResponse(region string, request *r_kvstore.DescribeInstanceAttributeRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := r_kvstore.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeInstanceAttribute(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Instances"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getRedisVInterfaceResponse(region string, request *r_kvstore.DescribeDBInstanceNetInfoRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := r_kvstore.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeDBInstanceNetInfo(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("NetInfoItems"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getRDSResponse(region string, request *rds.DescribeDBInstancesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := rds.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeDBInstances(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Items"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getRDSAttributeResponse(region string, request *rds.DescribeDBInstanceAttributeRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := rds.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeDBInstanceAttribute(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Items"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getRDSVInterfaceResponse(region string, request *rds.DescribeDBInstanceNetInfoRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := rds.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeDBInstanceNetInfo(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("DBInstanceNetInfos"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getNatGatewayResponse(region string, request *vpc.DescribeNatGatewaysRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeNatGateways(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("NatGateways"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getSNatRuleResponse(region string, request *vpc.DescribeSnatTableEntriesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeSnatTableEntries(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("SnatTableEntries"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getDNatRuleResponse(region string, request *vpc.DescribeForwardTableEntriesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := vpc.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeForwardTableEntries(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("ForwardTableEntries"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getLBResponse(region string, request *slb.DescribeLoadBalancersRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := slb.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeLoadBalancers(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("LoadBalancers"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getLBTargetServerResponse(region string, request *slb.DescribeHealthStatusRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := slb.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeHealthStatus(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("BackendServers"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getLBListenerResponse(region string, request *slb.DescribeLoadBalancerAttributeRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := slb.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	for {

		response, err := client.DescribeLoadBalancerAttribute(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("ListenerPortsAndProtocal"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		break
	}
	return resp, nil
}

func (a *Aliyun) getCenResponse(region string, request *cbn.DescribeCensRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := cbn.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeCens(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("Cens"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}

func (a *Aliyun) getCenAttributeResponse(region string, request *cbn.DescribeCenAttachedChildInstancesRequest) ([]*simplejson.Json, error) {
	var resp []*simplejson.Json

	client, _ := cbn.NewClientWithAccessKey(region, a.secretID, a.secretKey)
	pageNum := 1
	pageSize := 50
	totalCount := 0
	for {
		request.PageSize = requests.NewInteger(pageSize)
		request.PageNumber = requests.NewInteger(pageNum)

		response, err := client.DescribeCenAttachedChildInstances(request)
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if response.GetHttpStatus() != 200 {
			return make([]*simplejson.Json, 0), errors.New(response.GetHttpContentString())
		}

		result, err := simplejson.NewJson(response.GetHttpContentBytes())
		if err != nil {
			return make([]*simplejson.Json, 0), err
		}

		if curResp, ok := result.CheckGet("ChildInstances"); ok {
			resp = append(resp, curResp)
		} else {
			break
		}
		pageNum += 1
		totalCount += pageSize
		if totalCount >= result.Get("TotalCount").MustInt() {
			break
		}
	}
	return resp, nil
}