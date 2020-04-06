package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

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

// SimpleChaincode is
type SimpleChaincode struct {
}

var logger = shim.NewLogger("OUTPUT")

// Init is
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	//var erro error
	var orgName = "Admin"
	var creatorID = 0
	// 设置初始属性库
	aS := &Att{
		Name: "group",
		T:    Sub,
	}
	aSJson, err := json.Marshal(aS)
	if err != nil {
		return nil, err
	}
	s := orgName + strconv.Itoa(creatorID) + aS.Name + strconv.Itoa(int(aS.T))
	aSID := string(Hash([]byte(s)))

	aR := &Att{
		Name: "securitylevel",
		T:    Res,
	}
	aRJson, err := json.Marshal(aR)
	if err != nil {
		return nil, err
	}
	s = orgName + strconv.Itoa(creatorID) + aR.Name + strconv.Itoa(int(aR.T))
	aRID := string(Hash([]byte(s)))

	aE := &Att{
		Name: "inoffice",
		T:    Env,
	}
	aEJson, err := json.Marshal(aE)
	if err != nil {
		return nil, err
	}
	s = orgName + strconv.Itoa(creatorID) + aE.Name + strconv.Itoa(int(aE.T))
	aEID := string(Hash([]byte(s)))
	aA := &Att{
		Name: "read",
		T:    Act,
	}
	aAJson, err := json.Marshal(aA)
	if err != nil {
		return nil, err
	}
	s = orgName + strconv.Itoa(creatorID) + aA.Name + strconv.Itoa(int(aA.T))
	aAID := string(Hash([]byte(s)))

	// return nil, errors.New("Expecting integer value for asset holding")

	fmt.Printf("Initialize attributes %s,%s,%s,%s\n", aS.Name, aR.Name, aE.Name, aA.Name)
	logger.Infof("Initialize attributes %s,%s,%s,%s\n", aS.Name, aR.Name, aE.Name, aA.Name)
	// 写状态到账本
	err = stub.PutState(aSID, aSJson)
	if err != nil {
		return nil, err
	}
	err = stub.PutState(aRID, aRJson)
	if err != nil {
		return nil, err
	}
	err = stub.PutState(aEID, aEJson)
	if err != nil {
		return nil, err
	}
	err = stub.PutState(aAID, aAJson)
	if err != nil {
		return nil, err
	}

	return aSJson, nil
}

// Invoke is
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function == "create" {
		// 根据不同的Function值进入不同的功能函数
		return t.attributeCreator(stub, args)
	} else if function == "distribute" {
		return t.attributeDistributor(stub, args)
	}
	return nil, nil
}

// attributeCreator is
func (t *SimpleChaincode) attributeCreator(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 3")
	}
	var att Att
	orgName := args[0]
	creatorID := args[1]
	err := json.Unmarshal([]byte(args[3]), &att)
	if err != nil {
		return nil, errors.New("Json Unmarshal fail")
	}
	switch att.T {
	case Sub, Res, Env, Act:
	default:
		return nil, errors.New("Wrong attribute type")
	}
	s := orgName + creatorID + att.Name + strconv.Itoa(int(att.T))
	AID := string(Hash([]byte(s)))
	alBytes, err := stub.GetState(AID)
	// no AID key exists
	if err != nil {
		attJSON, err := json.Marshal(att)
		if err != nil {
			return nil, errors.New("Json Marshal fail")
		}
		err = stub.PutState(AID, attJSON)
		if err != nil {
			return nil, errors.New("Attribute Put fail")
		}
		return nil, nil
	}
	// existe AID but no val
	if alBytes == nil {
		attJSON, err := json.Marshal(att)
		if err != nil {
			return nil, errors.New("Json Marshal fail")
		}
		err = stub.PutState(AID, attJSON)
		if err != nil {
			return nil, errors.New("Attribute Put fail")
		}
		return []byte(AID), nil
	}
	return nil, errors.New("Attribute Create fail")
}

// attributeCreator is
func (t *SimpleChaincode) attributeDistributor(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 5 {
		return nil, errors.New("Incorrect number of arguments. Expecting 5")
	}
	var att Att
	applicantID := args[0]
	// if err != nil {
	// 	return nil, errors.New("Expecting integer value for asset holding")
	// }
	issuerID := args[1]
	AID := args[2]
	attVal := args[3]
	certOld := args[4]

	attJSON, err := stub.GetState(AID)
	// no AID key exists
	if err != nil {
		return nil, errors.New("no AID=" + AID + " key exists")
	}
	if attJSON == nil {
		return nil, errors.New("AID=" + AID + " attribute is not created ")
	}
	err = json.Unmarshal(attJSON, &att)
	if err != nil {
		return nil, errors.New("Json Unmarshal fail")
	}
	att.Val = attVal
	if certOld == "" {
		certNew, err := GenerateX509AttributeCertificate(applicantID, issuerID, AID, att)
		if err != nil {
			return nil, errors.New("GenerateX509Certificate fail")
		}
		return certNew, nil
	} else {
		certNew, err := AppendX509AttributeCertificate(certOld, applicantID, issuerID, AID, att)
		if err != nil {
			return nil, errors.New("AppendX509Certificate fail")
		}
		return certNew, nil
	}
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
	AID := args[0]
	// 从账本中获取AID的值
	attBytes, err := stub.GetState(AID)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + AID + "\"}"
		return nil, errors.New(jsonResp)
	}
	if attBytes == nil {
		jsonResp := "{\"Error\":\"Nil attribute for " + AID + "\"}"
		return nil, errors.New(jsonResp)
	}
	jsonResp := "{\"Name\":\"" + AID + "\",\"Attribute\":\"" + string(attBytes) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return attBytes, nil
}
func main() {
	// ChainCode 调用 err := shim.Start(new(SimpleChaincode))
	// 接入到ChainCodeSupportServer
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}

}

// hash==sha256
func Hash(n []byte) []byte {
	//使用sha256哈希函数
	h := sha256.New()
	h.Write([]byte(n))
	sum := h.Sum(nil)
	return sum
}
func GenerateX509AttributeCertificate(appid, issid, Aid string, att Att) ([]byte, error) {
	var atts = []Att{att}
	cer := &Certificate{
		ApplicantID: appid,
		IssuerID:    issid,
		AID:         Aid,
		Attribute:   atts,
	}
	cerJSON, err := json.Marshal(cer)
	if err != nil {
		return nil, errors.New("CertNew Marshal fail")
	}
	return cerJSON, errors.New("")
}
func AppendX509AttributeCertificate(cert, appid, issid, Aid string, att Att) ([]byte, error) {
	var c Certificate
	err := json.Unmarshal([]byte(cert), &c)
	if err != nil {
		return nil, errors.New("CertOld Unmarshal fail")
	}
	atts := append(c.Attribute, att)
	cer := &Certificate{
		ApplicantID: appid,
		IssuerID:    issid,
		AID:         Aid,
		Attribute:   atts,
	}
	cerJSON, err := json.Marshal(cer)
	if err != nil {
		return nil, errors.New("Cert Marshal fail")
	}
	return cerJSON, errors.New("")
}
