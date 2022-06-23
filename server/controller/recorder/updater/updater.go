package updater

import (
	"server/controller/recorder/cache"
	"server/controller/recorder/constraint"
	"server/controller/recorder/db"
)

// ResourceUpdater 实现资源进行新旧数据比对，并根据比对结果增删改资源
type ResourceUpdater interface {
	// 以资源的lcuuid为key，逐一检查cloud数据
	// 若cache的diff base中不存在，则添加
	// 若cache的diff base中存在，基于可更新字段，检查cloud数据是否发生变化，若发生变化，则更新；
	// 无论已存在资源有无变化，根据cache的sequence更新的diff base中的sequence，用于标记资源是否需要被删除
	HandleAddAndUpdate()
	// 逐一检查diff base中的资源，若sequence不等于cache中的sequence，则删除
	HandleDelete()
}

type DataGenerator[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase[MT]] interface {
	// 根据cloud数据获取对应的diff base数据
	getDiffBaseByCloudItem(*CT) (BT, bool)
	// 生成插入DB所需的数据
	generateDBItemToAdd(*CT) (*MT, bool)
	// 生产更新DB所需的数据
	generateUpdateInfo(BT, *CT) (map[string]interface{}, bool)
}

type CacheHandler[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase[MT]] interface {
	// 根据新增的db数据，更新cache
	addCache([]*MT)
	// 根据更新的db数据，更新cache
	updateCache(*CT, BT)
	// 根据删除的db数据，更新cache
	deleteCache([]string)
}

type UpdaterBase[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase[MT]] struct {
	cache         *cache.Cache
	dbOperator    db.Operator[MT]           // 数据库操作对象
	diffBaseData  map[string]BT             // 用于比对的旧资源数据
	cloudData     []CT                      // 定时获取的新资源数据
	dataGenerator DataGenerator[CT, MT, BT] // 提供各类数据生成的方法
	cacheHandler  CacheHandler[CT, MT, BT]  // 提供处理cache中特定资源的方法
}

func (u *UpdaterBase[CT, MT, BT]) HandleAddAndUpdate() {
	dbItemsToAdd := []*MT{}
	for _, cloudItem := range u.cloudData {
		diffBase, exists := u.dataGenerator.getDiffBaseByCloudItem(&cloudItem)
		if !exists {
			dbItem, ok := u.dataGenerator.generateDBItemToAdd(&cloudItem)
			if ok {
				dbItemsToAdd = append(dbItemsToAdd, dbItem)
			}
		} else {
			diffBase.SetSequence(u.cache.GetSequence())
			updateInfo, ok := u.dataGenerator.generateUpdateInfo(diffBase, &cloudItem)
			if ok {
				u.update(&cloudItem, diffBase, updateInfo)
			}
		}
	}
	if len(dbItemsToAdd) > 0 {
		u.add(dbItemsToAdd)
	}
}

func (u *UpdaterBase[CT, MT, BT]) HandleDelete() {
	lcuuidsOfBatchToDelete := []string{}
	for lcuuid, diffBase := range u.diffBaseData {
		if diffBase.GetSequence() != u.cache.GetSequence() {
			lcuuidsOfBatchToDelete = append(lcuuidsOfBatchToDelete, lcuuid)
		}
	}
	if len(lcuuidsOfBatchToDelete) > 0 {
		u.delete(lcuuidsOfBatchToDelete)
	}
}

// 创建资源，按序操作DB、cache、资源变更事件
func (u *UpdaterBase[CT, MT, BT]) add(dbItemsToAdd []*MT) {
	count := len(dbItemsToAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		u.addPage(dbItemsToAdd[start:end])
	}
}

func (u *UpdaterBase[CT, MT, BT]) addPage(dbItemsToAdd []*MT) {
	addedDBItems, ok := u.dbOperator.AddBatch(dbItemsToAdd)
	if ok {
		u.cacheHandler.addCache(addedDBItems)
	}
}

// 更新资源，按序操作DB、cache、资源变更事件
func (u *UpdaterBase[CT, MT, BT]) update(cloudItem *CT, diffBase BT, updateInfo map[string]interface{}) {
	_, ok := u.dbOperator.Update(diffBase.GetLcuuid(), updateInfo)
	if ok {
		u.cacheHandler.updateCache(cloudItem, diffBase)
	}
}

// 删除资源，按序操作DB、cache、资源变更事件
func (u *UpdaterBase[CT, MT, BT]) delete(lcuuids []string) {
	count := len(lcuuids)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		u.deletePage(lcuuids[start:end])
	}
}

func (u *UpdaterBase[CT, MT, BT]) deletePage(lcuuids []string) {
	if u.dbOperator.DeleteBatch(lcuuids) {
		u.cacheHandler.deleteCache(lcuuids)
	}
}