---
title: "管理系统api"
date: 2020-03-21T20:49:19+08:00
draft: true
---
# 用户管理
## 登录
POST /api/user/login  
入参：  
```json
{
    "userName":"admin",
    "password":"123456"
}
```

出参：
```json
{
    "code": 1,
    "data": {
        "userId": "用户id",
        "userName": "用户名称",
        "deptId": "部门id",
        "deptName": "部门名称",
        "token": "token"
    }
}
```

# 企业档案
企业档案、子公司对象结构
```json
{
    "code": "001", 
    "brand":"企业品牌",
    "name":"企业全称",
    "shortName":"企业简称",
    "companyType":"企业类型",
    "address":"公司地址",
    "zipCode":"邮编",
    "email":"邮箱",
    "phone":"电话",
    "fax":"传真",
    "bank":"开户银行",
    "bankAccount":"银行账号",
    "website": "网址",
    "nationalTaxNo": "国税号",
    "regionalTaxNo": "地税号",
    "remarks":"备注"
}
```

## 查询企业档案
GET /api/company/getCompanyInfo  
入参：无  
出参：
```json
{
    "code": 1,
    "data": {obj}
}
```

## 查询子公司列表
GET /api/company/GetSubCompanytList  
入参： 无  
出参：  
```json
{
    "code": 1,
    "data": [
        {obj}
    ]
}
```

## 修改企业档案
POST /api/company/update  
入参：
```json
{obj}
```
出参：
```json
{
    "code": 1,
    "data": true
}
```

## 新增下属公司
POST /api/company/addSubCompany  
入参：
```json
{obj}
```
出参：
```json
{
    "code": 1,
    "data": true
}
```
## 更新子公司
POST /api/company/updateSubCompany  
入参：  
```json
{obj}
```
出参:  
```json
{
    "code": 1,
    "data": true
}
```
## 查询子公司信息
GET company/getSubCompanyInfo?code={code}  
入参：code, 子公司编码  
出参：  
```json
{
    "code": 1,
    "data": {obj}
}
```

# 部门管理
部门对象结构
```json
{
    "id": 234, 
    "superiorDeptName": "上级部门名称", 
    "code": "部门编码",
    "name": "部门名称",
    "responsiblePerson": "负责人名称",
    "phone": "电话号码",
    "fax": "传真",
    "type": 0, //部门类型0无 客服部门 = 321,销售部门 = 322,常规部门 = 554
    "isAllowManageSubDeptData": true, //是否允许管理下级部门数据
    "remarks": "备注"
}
```
## 查询部门树形列表
GET /department/getTree  
入参：无  
出参：  
```json
{
    "code": 1,
    "data": {
        "id": 1,
        "code": "001",
        "name": "黑河市热费部门",
        "children": [
            {
                "id": 234,
                "code": "编码",
                "name": "名称",
                "children": null
            }
        ]
    }
}
```

## 查询部门
GET /department/getById?id={id}  
入参：id,部门id  
出参：
```json
{
    "code": 1,
    "data": {obj}
}
```

## 更新部门
POST /api/department/update  
入参： 
```json
{obj}
```
出参：  
```json
{
    "code": 1,
    "data": true
}
```

## 删除部门
POST /api/department/delete  
入参：
```json
{
    "id": 230
}
```
出参：
```json
{
    "code": 1,
    "data": true
}
```
# 职位管理
职位业务对象结构
```json
{
    "id": 1,
    "name": "超级管理员",
    "newName": "新岗位名",
    "description": "职位描述",
    "responsibility": "岗位职责",
    "createdBy": "admin",
    "createdOn": "2018-06-29 13:28:00"
}
```
## 职位列表
GET /api/position/getList  
入参：无  
出参：
```json
{
    "code": 1,
    "data": {obj}
}
```
## 新增职位
POST /api/position/add
入参
```json
{obj}
```
出参
```json
{
    "code": 1,
    "data": {obj}
}
```  
## 删除职位
POST /api/position/delete  
入参:
```json
{
    "id":1
}
```
## 更新职位
POST /api/position/update
入参：
```json
{obj}
```
## 设置岗位职责
POST /api/position/updatePositionReponsibility  
入参：
```json
{obj}
```
## 查询职位
GET /api/position/getById?id={id}
出参：
```json
{
    "code": 1,
    "data": {obj}
}
```
# 角色管理
角色业务对象结构
```json
{
     "id": 52,
    "roleName": "角色名称",
    "remarks": "备注",
    "createdBy": "创建人",
    "createdOn": "2020-03-20 23:43:34"
}
```
## 查询角色列表
GET /api/role/getList?keywords={keywords}  
出参：  
```json
{
    "code": 1,
    "data": [
        {obj}
    ]
}
```

## 新增角色
POST /api/role/add
入参：  
```json
{obj}
```
## 修改角色
POST /api/role/update
入参
```json
{obj}
```
## 删除角色
POST /api/role/delete
入参
```json
{"id":1}
```
## 查询角色模块权限树
GET /api/role/getRoleModuleRights?roleId={roleId}  
出参：
```json
{
    "code": 1,
    "data": [
        {
            "id": 101,
            "name": "停热管理", 
            "hasRight": null, //非末级不适用
            "children": [
                {
                    "id": 102,
                    "name": "供热报停单查询",
                    "hasRight": false, //角色是否有权限
                    "children": null
                }
            ]
        }
    ]
}
```

## 保存角色模块权限
POST /api/role/saveRoleModuleRights  
入参：
```json
{
  "roleId": 1,
  "moduleIds": [
    1,
    2,
    3
  ]
}
```

## 操作权限 - TODO

# 用户管理
## 用户列表
GET /api/user/getList
入参： 
```
deptId：部门id
code：用户编码
name：姓名
gender：性别，男/女
status：正常/禁用/建档
mobile：移动电话
officephone：办公电话
position：职位
roleName：角色名
companyName：公司名
```
出参：
```json
{
    "code": 1,
    "data": [
        {
            "code": "test",
            "name": "测试",
            "gender": null,
            "deptName": null,
            "position": "0",
            "roleName": null,
            "mobile": "",
            "status": "正常",
            "companyName": null,
            "createdOn": null,
            "officePhone": null,
            "roleCount": 0
        }
    ]
}
```



