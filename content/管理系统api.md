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

## 新增用户
POST /api/user/addUser   
入参：  
```csharp
{
  "employeeId": 0, //员工id
  "code": "string", //编码
  "password": "string", //密码
  "confirmPassword": "string",
  "roleId": 0, //角色id
  "effectiveDate": "2020-03-23T04:45:58.957Z", //生效时间
  "expireDate": "2020-03-23T04:45:58.957Z", //过期时间
  "remarks": "string", //备注
  "status": "string", //用户状态 正常/禁用/建档/删除
  "isDeptAdmin": true, //是否部门管理人员
  "isAllRegionAdmin": true, //是否所有区域管理
  "email": "string", //邮箱
  "mobile": "string", //手机
  "officePhone": "string", //办公电话
  "internalPhone": "string", //内线电话
  "isContractApprover": true, //是否合同审批人员
  "isContractConfirmer": true //是否合同确认人员
}
```
## 删除用户
POST /api/user/deleteUser  
入参
```json
{
    "id":"string"
}
```
## 更新用户
POST /api/user/updateUser  
入参
```json
{
  "code": "string",
  "companyId": "string",
  "departmentId": 0,
  "positionId": 0,
  "roleId": 0,
  "effectiveDate": "2020-03-23T05:28:22.449Z",
  "expireDate": "2020-03-23T05:28:22.449Z",
  "birthday": "2020-03-23T05:28:22.449Z",
  "status": "string",
  "isDeptAdmin": true,
  "isAllRegionAdmin": true,
  "officePhone": "string",
  "internalPhone": "string",
  "isContractApprover": true,
  "isContractConfirmer": true
}
```

## 查询用户
GET /api/user/getUserById?id={id}  
入参：
```json
{
  "code": 1,
  "data": {
    "code": "string",
    "companyId": "string",
    "departmenttId": 0,
    "positionId": 0,
    "roleId": 0,
    "effectiveDate": "2020-03-23T05:29:04.181Z",
    "expireDate": "2020-03-23T05:29:04.181Z",
    "birthday": "2020-03-23T05:29:04.181Z",
    "status": "string",
    "isDeptAdmin": true,
    "isAllRegionAdmin": true,
    "officePhone": "string",
    "internalPhone": "string",
    "isContractApprover": true,
    "isContractConfirmer": true
  }
}
```

## 导出用户
POST /api/user/export  
**Content-Type:form-data**
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
## 查询用户角色
GET /api/user/getUserRoles?userId={userId}
出参
```json
{
  "code": 0,
  "data": [
    {
      "id": 0,
      "roleName": "string",
      "remarks": "string",
      "createdBy": "string",
      "createdOn": "2020-03-23T05:30:58.558Z"
    }
  ]
}
```
## 新增用户角色
POST /api/user/addUserRoles  
入参：
```json
{
  "userId": "string",
  "roleIds": [
    0
  ]
}
```
## 删除用户角色
POST /api/user/deleteUserRoles
入参：
```json
{
  "userId": "string",
  "roleIds": [
    0
  ]
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

## 新增部门
POST /api/department/add
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

# 分组管理
## 新增分组
POST /api/group/add
```json
{
  "name": "string",
  "description": "string"
}
```
## 删除分组
POST /api/group/delete
```json
{
  "id": "string"
}
```

## 更新分组
POST /api/group/update
```json
{
  "id": 0,
  "name": "string",
  "description": "string"
}
```

## 查询分组
GET /api/group/getById?id={id}  
出参：
```json
{
  "code": 0,
  "data": {
    "id": 0,
    "name": "string",
    "description": "string"
  }
}
```

## 查询分组列表
GET /api/group/getList  
出参：
```json
{
  "code": 0,
  "data": [
    {
      "id": 0,
      "name": "string",
      "description": "string"
    }
  ]
}
```
## 查询分组待办授权列表
GET /api/group/getGroupTodoList?groupId={groupId}  
出参：  
```json
{
  "code": 0,
  "data": {
    "todoId": 0,
    "todoName": "string",
    "status": "string",
    "type": "string",
    "hasRight": true
  }
}
```

## 新增分组待办授权
POST /api/group/addGroupTodo  
入参：  
```json
{
    "groupId":0,
    "todoId":0
}
```
## 删除分组待办授权
POST /api/group/deleteGroupTodo  
入参：  
```json
{
    "groupId":0,
    "todoId":0
}
```
## 新增分组-用户、职位、角色关联
POST /api/group/addGroupUser
入参：
```json
{
  "groupId": 0,
  "objectId": "string", //对象id
  "objectType": "string" //对象类型
}
```

## 删除分组-用户、职位、角色关联
POST /api/group/deleteGroupUser  
入参：
```json
{
  "groupId": 0,
  "objectId": "string", //对象id
  "objectType": "string" //对象类型
}
```

# 日志查询
## 查询登录汇总日志列表
GET /api/log/getLoginLogSummary?userCode=x&startTime=x&endTime=x
出参  
```json
{
  "code": 0,
  "data": [
    {
      "userCode": "string",
      "userName": "string",
      "loginCount": 0
    }
  ]
}
```

## 查询登录日志分页列表
GET /api/log/getLoginLogList?pageNo=1&pageSize=10&usercode=x&startTime=x
&endTime=x&module=x&ip=x&status=x
出参  
```json
{
  "code": 0,
  "data": [
    {
      "loginDate": "string",
      "userCode": "string",
      "userName": "string",
      "ip": "string",
      "port": "string",
      "status": "string",
      "module": "string"
    }
  ]
}
```

