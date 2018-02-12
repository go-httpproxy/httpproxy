package authdigest

import (
	"crypto/rand"
	"fmt"
	"time"
)

type OpaqueInfo struct {
	Realm      string
	Nonce      string
	Opaque     string
	Method     string
	RequestURI string
	Tm         *time.Time
	ReqCount   int
}

type OpaqueInfoStorge interface {
	Get(opaque string) *OpaqueInfo
	Set(opaque string, oi *OpaqueInfo)
	Del(opaque string)
}

type AuthDigest struct {
	expireDuration time.Duration
	expireReqCount int
}

func NewAuthDigest(expireDuration time.Duration, expireReqCount int) *AuthDigest {
	return &AuthDigest{expireDuration: expireDuration, expireReqCount: expireReqCount}
}

func (ad *AuthDigest) Start() {

}

func genRnd(size int) string {
	b := make([]byte, size)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
