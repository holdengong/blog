---
title: "管理系统api"
date: 2020-03-21T20:49:19+08:00
draft: false
---
#### 1：登录
POST /api/user/login
```json
{
    "userName":"admin",
    "password":"123456"
}
```

#### 2：查询企业档案
GET /api/company/getCompanyInfo  
入参：无  
出参：
```json
{
    "code": 1,
    "data": {
        "id": "001", 
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
        "remarks":"备注"
    }
}
```

#### 3：修改企业档案
POST /api/company/update  
入参：
```json
{
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
    "remarks":"备注"
}
```
出参：
```json
{
    "code": 1,
    "data": true
}
```

### 4：新增下属公司
POST /api/company/addSubCompany
入参：
```json
{
  "code":"公司编码",
  "name":"公司全称",
  "shortName":"公司简称",
  "address":"地址",
  "zipCode":"邮编",
  "email":"邮箱",
  "phone":"电话",
  "fax":"传真",
  "bank":"开户银行",
  "bankAccount":"银行账号",
  "remarks":"备注"
}
```
出参：
```json
{
    "code": 1,
    "data": true
}
```