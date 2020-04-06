package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

type AttType int

const (
	Sub AttType = iota + 1
	Res
	Env
	Act
)

type Req struct {
	Reql   string `json:"req_l"`
	Resl   string `json:"res_l"`
	Action string `json:"action"`
	E      []byte `json:"e_bytes"`
}
type Certificate struct {
	ApplicantID string `json:"app_id"`
	IssuerID    string `json:"iss_id"`
	AID         string `json:"a_id"`
	Attribute   []Att  `json:"atts"`
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
type Tx struct {
	Req       Req   `json:"req"`
	Decision  bool  `json:"dec"`
	Timestamp int64 `json:"ts"`
}

// SimpleChaincode is
type SimpleChaincode struct {
}

// Init is
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	return nil, nil
}

// Invoke is
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function == "evaluate" {
		// 根据不同的Function值进入不同的功能函数
		return t.policyEvaluator(stub, args)
	}
	return nil, nil
}

// attributeCreator is 𝑅𝑒𝑞 = (𝑅𝑒𝑞𝐿, 𝑅𝑒𝑠𝐿, 𝑎𝑐𝑡𝑖𝑜𝑛, 𝐸)%!"#𝐸=𝐸𝑛𝑐(𝑘,𝑃𝑘!$)
func (t *SimpleChaincode) policyEvaluator(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 4 {
		return nil, errors.New("Incorrect number of arguments. Expecting 4")
	}
	var req Req
	var certSub Certificate
	var attREA AttList
	var policy Policy
	var attRes []Att
	var attEnv []Att
	var attAct []Att

	err := json.Unmarshal([]byte(args[0]), &req)
	if err != nil {
		return nil, errors.New("Json req Unmarshal fail")
	}
	err = json.Unmarshal([]byte(args[1]), &certSub)
	if err != nil {
		return nil, errors.New("Json req Unmarshal fail")
	}
	err = json.Unmarshal([]byte(args[2]), &attREA)
	if err != nil {
		return nil, errors.New("Json req Unmarshal fail")
	}
	policyID := args[3]

	attSub := certSub.Attribute
	for _, att := range attREA.AttList {
		switch att.T {
		case Res:
			attRes = append(attRes, att)
		case Env:
			attEnv = append(attEnv, att)
		case Act:
			attAct = append(attAct, att)
		default:
			return nil, errors.New("Wrong type attREA")
		}
	}
	policyJSON, err := stub.GetState(policyID)
	if err != nil {
		return nil, errors.New("no policyID exists")
	}
	// existe AID but no val
	if policyJSON == nil {
		return nil, errors.New("policyID have no val")
	}

	err = json.Unmarshal(policyJSON, &policy)
	if err != nil {
		return nil, errors.New("policyJSON Unmarshal fail")
	}
	result := policyEvaluate(policy, attSub, attRes, attEnv, attAct)

	tx := &Tx{
		Req:       req,
		Decision:  result,
		Timestamp: time.Now().Unix(),
	}
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return nil, errors.New("tx Marshal fail")
	}
	txid := Hash(txJSON)
	err = stub.PutState(string(txid), txJSON)
	if err != nil {
		return nil, errors.New("Put txid fail")
	}

	if result == true {
		return txid, nil
	}
	return nil, errors.New("The Request rejected")
}

func policyEvaluate(p Policy, atts, attr, atte, atta []Att) bool {
	result := isSatisfiedBy(p.SubPolicy, atts) && isSatisfiedBy(p.ResPolicy, attr) && isSatisfiedBy(p.EnvPolicy, atte) && isSatisfiedBy(p.ActPolicy, atta)
	return result
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
	txID := args[0]
	// 从账本中获取AID的值
	TxBytes, err := stub.GetState(txID)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + txID + "\"}"
		return nil, errors.New(jsonResp)
	}
	if TxBytes == nil {
		jsonResp := "{\"Error\":\"Nil Tx for " + txID + "\"}"
		return nil, errors.New(jsonResp)
	}
	jsonResp := "{\"Name\":\"" + txID + "\",\"Tx\":\"" + string(TxBytes) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return TxBytes, nil
}
func main() {
	// ChainCode 调用 err := shim.Start(new(SimpleChaincode))
	// 接入到ChainCodeSupportServer
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
func isSatisfiedBy(policy, atts []Att) bool {
	for _, policyatt := range policy {
		flag := false
		for _, att := range atts {
			if (policyatt.Name == att.Name) && (policyatt.Val == att.Val) {
				flag = true
			}
		}
		if flag == true {
			continue
		} else {
			return false
		}
	}
	return true
}

//hash==sha256
func Hash(n []byte) []byte {
	//使用sha256哈希函数
	h := sha256.New()
	h.Write([]byte(n))
	sum := h.Sum(nil)
	return sum
}
