package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type VM struct {
	UpdaterBase[cloudmodel.VM, mysql.VM, *cache.VM]
}

func NewVM(wholeCache *cache.Cache, cloudData []cloudmodel.VM) *VM {
	updater := &VM{
		UpdaterBase[cloudmodel.VM, mysql.VM, *cache.VM]{
			cache:        wholeCache,
			dbOperator:   db.NewVM(),
			diffBaseData: wholeCache.VMs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (m *VM) getDiffBaseByCloudItem(cloudItem *cloudmodel.VM) (diffBase *cache.VM, exists bool) {
	diffBase, exists = m.diffBaseData[cloudItem.Lcuuid]
	return
}

func (m *VM) generateDBItemToAdd(cloudItem *cloudmodel.VM) (*mysql.VM, bool) {
	vpcID, exists := m.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.VM{
		Name:         cloudItem.Name,
		Label:        cloudItem.Label,
		UID:          cloudItem.Label,
		State:        cloudItem.State,
		HType:        cloudItem.HType,
		LaunchServer: cloudItem.LaunchServer,
		Domain:       m.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		VPCID:        vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if !cloudItem.CreatedAt.IsZero() {
		dbItem.CreatedAt = cloudItem.CreatedAt
	}
	return dbItem, true
}

func (m *VM) generateUpdateInfo(diffBase *cache.VM, cloudItem *cloudmodel.VM) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := m.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				common.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["epc_id"] = vpcID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if diffBase.State != cloudItem.State {
		updateInfo["state"] = cloudItem.State
	}
	if diffBase.HType != cloudItem.HType {
		updateInfo["htype"] = cloudItem.HType
	}
	if diffBase.LaunchServer != cloudItem.LaunchServer {
		updateInfo["launch_server"] = cloudItem.LaunchServer
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return updateInfo, false
}

func (m *VM) addCache(dbItems []*mysql.VM) {
	m.cache.AddVMs(dbItems)
}

func (m *VM) updateCache(cloudItem *cloudmodel.VM, diffBase *cache.VM) {
	diffBase.Update(cloudItem)
}

func (m *VM) deleteCache(lcuuids []string) {
	m.cache.DeleteVMs(lcuuids)
}