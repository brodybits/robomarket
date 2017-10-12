package robomarket

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

type (
	formatType   int
	hashType     int
	requestType  int
	responseType int
)

const (
	signatureHeaderName = "RoboSignature"
)

var IncorrectSignature = fmt.Errorf("Signature is incorrect")

const (
	HashTypeMD5 hashType = iota
	HashTypeSHA1
)
const (
	ReservationRequest requestType = iota
	PurchaseRequest
	CancellationRequest
	YaReservationRequest
)
const (
	ReservationSuccess responseType = iota
	ReservationFailure
	PurchaseResponse
	CancellationResponse
)

type request struct {
	OrderId   string
	TotalCost float32
	InvoiceId string
	Customer  struct {
		Name  string
		Email string
		Phone string
	}
	CustomerComment string
	Items           []*item
}
type item struct {
	OfferId   string
	TotalCost float32
	Quantity  float32
	Price     float32
	Title     struct {
		Value string
	}
	Delivery *delivery
}
type delivery struct {
	DeliveryType    string
	DeliveryPackage int
	Price           float32
	Region          string
	City            string
	Address         string
}

type Client struct {
	secret   string
	hashType hashType
}

func NewClient(secret string, hashType hashType) *Client { // only JSON format is supported
	return &Client{secret, hashType}
}

func (c *Client) checkSignature(r *http.Request) error {
	var (
		hash hash.Hash
		buf  bytes.Buffer
	)
	switch c.hashType {
	case HashTypeMD5:
		hash = md5.New()
	case HashTypeSHA1:
		hash = sha1.New()
	}
	writer := io.MultiWriter(&buf, hash) // simultaneously write to both buffer and hash
	sig := r.Header.Get(signatureHeaderName)
	if _, err := io.Copy(writer, r.Body); err != nil {
		return err
	}
	r.Body = ioutil.NopCloser(&buf) // return back request Body (recreate from buffer)
	hash.Write([]byte(c.secret))
	expSig := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(expSig, sig) {
		return IncorrectSignature
	}
	return nil
}

func (c *Client) addSignature(rw http.ResponseWriter, b []byte) {
	var hash hash.Hash
	switch c.hashType {
	case HashTypeMD5:
		hash = md5.New()
	case HashTypeSHA1:
		hash = sha1.New()
	}
	hash.Write(b)
	hash.Write([]byte(c.secret))
	sig := hash.Sum(nil)
	rw.Header().Add(signatureHeaderName, hex.EncodeToString(sig))
}

func (c *Client) HandleRequest(r *http.Request) (requestType requestType, req *request, err error) {
	if err = c.checkSignature(r); err != nil {
		return
	}
	decoder := json.NewDecoder(r.Body)
	var root struct {
		Robomarket struct {
			ReservationRequest   *request
			PurchaseRequest      *request
			CancellationRequest  *request
			YaReservationRequest *request
		}
	}
	err = decoder.Decode(&root)
	if err != nil {
		return
	}
	switch {
	case root.Robomarket.ReservationRequest != nil:
		requestType = ReservationRequest
		req = root.Robomarket.ReservationRequest
	case root.Robomarket.PurchaseRequest != nil:
		requestType = PurchaseRequest
		req = root.Robomarket.PurchaseRequest
	case root.Robomarket.CancellationRequest != nil:
		requestType = CancellationRequest
		req = root.Robomarket.CancellationRequest
	case root.Robomarket.YaReservationRequest != nil:
		requestType = YaReservationRequest
		req = root.Robomarket.YaReservationRequest
	default:
		err = fmt.Errorf("No valid request type recognized")
		return
	}
	return
}

func (c *Client) Respond(rw http.ResponseWriter, rt responseType, fields interface{}) error {
	var response struct {
		Robomarket map[string]interface{}
	}
	response.Robomarket = make(map[string]interface{})
	switch rt {
	case ReservationSuccess:
		response.Robomarket["ReservationSuccess"] = fields
	case ReservationFailure:
		response.Robomarket["ReservationFailure"] = fields
	case PurchaseResponse:
		response.Robomarket["PurchaseResponse"] = fields
	case CancellationResponse:
		response.Robomarket["CancellationResponse"] = fields
	}
	b, err := json.Marshal(response)
	if err != nil {
		return err
	}
	c.addSignature(rw, b)
	rw.Write(b)
	return nil
}
