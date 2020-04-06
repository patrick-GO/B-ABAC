package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

type AttType int

const (
	Sub AttType = iota + 1
	Res
	Env
	Act
)

type Certificate struct {
	ApplicantID string `json:"app_id"`
	IssuerID    string `json:"iss_id"`
	AID         string `json:"a_id"`
	Attribute   []Att  `json:"att_s"`
}
type Att struct {
	Name string  `json:"att_name"`
	T    AttType `json:"att_type"`
	Val  string  `json:"att_val"`
}
type AttList struct {
	AttList []Att `json:"att_list"`
}
type Policy struct {
	SubPolicy []Att `json:"sub_policy"`
	ResPolicy []Att `json:"res_policy"`
	EnvPolicy []Att `json:"env_policy"`
	ActPolicy []Att `json:"act_policy"`
}

// SimpleChaincode is
type SimpleChaincode struct {
}

// Init is
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	//元策略
	return nil, nil
}

// Invoke is
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function == "create" {
		// 根据不同的Function值进入不同的功能函数
		return t.policyCreator(stub, args)
	} else if function == "revoke" {
		return t.policyRevoker(stub, args)
	}
	return nil, nil
}

// attributeCreator is
func (t *SimpleChaincode) policyCreator(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 5 {
		return nil, errors.New("Incorrect number of arguments. Expecting 5")
	}
	var certRes Certificate
	var attRequire AttList
	var act Att
	var attAct = []Att{}
	resID := args[0]
	creatorID := args[1]
	ID := resID + creatorID
	action := args[2]
	switch action {
	case "read":
		act.Name = "read"
		act.T = Act
		act.Val = ""
	case "write":
		act.Name = "write"
		act.T = Act
		act.Val = ""
	case "delete":
		act.Name = "delete"
		act.T = Act
		act.Val = ""
	default:
		return nil, errors.New(ID + "Wrong action")
	}
	err := json.Unmarshal([]byte(args[3]), &attRequire)
	if err != nil {
		return nil, errors.New("Json attRequire Unmarshal fail")
	}
	err = json.Unmarshal([]byte(args[4]), &certRes)
	if err != nil {
		return nil, errors.New("Json certRes Unmarshal fail")
	}
	attRes := certRes.Attribute
	var attSub = []Att{}
	var attEnv = []Att{}
	for _, att := range attRequire.AttList {
		switch att.T {
		case Sub:
			attSub = append(attSub, att)
		case Env:
			attEnv = append(attEnv, att)
		default:
			return nil, errors.New("attRequire contains wrong type att")
		}
	}
	policy := &Policy{
		SubPolicy: attSub,
		ResPolicy: attRes,
		EnvPolicy: attEnv,
		ActPolicy: attAct,
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, errors.New("Json Marshal fail")
	}
	policyID := string(Hash(policyJSON))

	policyBytes, err := stub.GetState(policyID)
	// no AID key exists
	if err != nil {
		stub.PutState(policyID, policyJSON)
		if err != nil {
			return nil, errors.New("Policy Put fail")
		}
		fmt.Printf("Policy:" + policyID + "create success")
		return nil, nil
	}
	// existe AID but no val
	if policyBytes == nil {
		stub.PutState(policyID, policyJSON)
		if err != nil {
			return nil, errors.New("Policy Put fail")
		}
		fmt.Printf("Policy:" + policyID + "create success")
		return nil, nil
	}
	return nil, errors.New("Policy Create fail")
}

//policyRevoker is
func (t *SimpleChaincode) policyRevoker(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 5")
	}
	resID := args[0]
	creatorID := args[1]
	ID := resID + creatorID
	policyID := args[2]
	policyJSON, err := stub.GetState(policyID)
	if err != nil {
		return nil, errors.New(ID + "no policyID exists")
	}
	// existe AID but no val
	if policyJSON == nil {

		return nil, errors.New("policyID have no val")
	}
	err = stub.DelState(policyID)
	if err != nil {
		return nil, errors.New("policy revoker success")
	}
	return nil, nil
}

// Query callback representing the query of a chaincode
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function != "query" {
		return nil, errors.New("Invalid query function name. Expecting \"query\"")
	}
	var err error
	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting name of the person to query")
	}
	policyID := args[0]
	// 从账本中获取AID的值
	policyBytes, err := stub.GetState(policyID)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + policyID + "\"}"
		return nil, errors.New(jsonResp)
	}
	if policyBytes == nil {
		jsonResp := "{\"Error\":\"Nil policy for " + policyID + "\"}"
		return nil, errors.New(jsonResp)
	}
	jsonResp := "{\"Name\":\"" + policyID + "\",\"policy\":\"" + string(policyBytes) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return policyBytes, nil
}
func main() {
	// ChainCode 调用 err := shim.Start(new(SimpleChaincode))
	// 接入到ChainCodeSupportServer
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}

//hash==sha256
func Hash(n []byte) []byte {
	//使用sha256哈希函数
	h := sha256.New()
	h.Write([]byte(n))
	sum := h.Sum(nil)
	return sum
}
