package nip44_test

import (
	"encoding/hex"
	"testing"

	"git.ekzyis.com/ekzyis/nip44"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

func assertCryptPriv(t *testing.T, sk1 string, sk2 string, conversationKey string, salt string, plaintext string, expected string) {
	var (
		k1        []byte
		s         []byte
		actual    string
		decrypted string
		ok        bool
		err       error
	)
	k1, err = hex.DecodeString(conversationKey)
	if ok = assert.NoErrorf(t, err, "hex decode failed for conversation key: %v", err); !ok {
		return
	}
	if ok = assertConversationKeyGenerationSec(t, sk1, sk2, conversationKey); !ok {
		return
	}
	s, err = hex.DecodeString(salt)
	if ok = assert.NoErrorf(t, err, "hex decode failed for salt: %v", err); !ok {
		return
	}
	actual, err = nip44.Encrypt(k1, plaintext, &nip44.EncryptOptions{Salt: s})
	if ok = assert.NoError(t, err, "encryption failed: %v", err); !ok {
		return
	}
	if ok = assert.Equalf(t, expected, actual, "wrong encryption"); !ok {
		return
	}
	decrypted, err = nip44.Decrypt(k1, expected)
	if ok = assert.NoErrorf(t, err, "decryption failed: %v", err); !ok {
		return
	}
	assert.Equal(t, decrypted, plaintext, "wrong decryption")
}

func assertCryptPub(t *testing.T, sk1 string, pub2 string, conversationKey string, salt string, plaintext string, expected string) {
	var (
		k1        []byte
		s         []byte
		actual    string
		decrypted string
		ok        bool
		err       error
	)
	k1, err = hex.DecodeString(conversationKey)
	if ok = assert.NoErrorf(t, err, "hex decode failed for conversation key: %v", err); !ok {
		return
	}
	if ok = assertConversationKeyGenerationPub(t, sk1, pub2, conversationKey); !ok {
		return
	}
	s, err = hex.DecodeString(salt)
	if ok = assert.NoErrorf(t, err, "hex decode failed for salt: %v", err); !ok {
		return
	}
	actual, err = nip44.Encrypt(k1, plaintext, &nip44.EncryptOptions{Salt: s})
	if ok = assert.NoError(t, err, "encryption failed: %v", err); !ok {
		return
	}
	if ok = assert.Equalf(t, expected, actual, "wrong encryption"); !ok {
		return
	}
	decrypted, err = nip44.Decrypt(k1, expected)
	if ok = assert.NoErrorf(t, err, "decryption failed: %v", err); !ok {
		return
	}
	assert.Equal(t, decrypted, plaintext, "wrong decryption")
}

func assertDecryptFail(t *testing.T, sk1 string, pub2 string, conversationKey string, ciphertext string, msg string) {
	var (
		k1  []byte
		ok  bool
		err error
	)
	k1, err = hex.DecodeString(conversationKey)
	if ok = assert.NoErrorf(t, err, "hex decode failed for conversation key: %v", err); !ok {
		return
	}
	if ok = assertConversationKeyGenerationPub(t, sk1, pub2, conversationKey); !ok {
		return
	}
	_, err = nip44.Decrypt(k1, ciphertext)
	assert.ErrorContains(t, err, msg)
}

func assertConversationKeyGeneration(t *testing.T, sendPrivkey *secp256k1.PrivateKey, recvPubkey *secp256k1.PublicKey, conversationKey string) bool {
	var (
		actualConversationKey   []byte
		expectedConversationKey []byte
		ok                      bool
		err                     error
	)
	expectedConversationKey, err = hex.DecodeString(conversationKey)
	if ok = assert.NoErrorf(t, err, "hex decode failed for conversation key: %v", err); !ok {
		return false
	}
	actualConversationKey = nip44.GenerateConversationKey(sendPrivkey, recvPubkey)
	if ok = assert.Equalf(t, expectedConversationKey, actualConversationKey, "wrong conversation key"); !ok {
		return false
	}
	return true
}

func assertConversationKeyGenerationSec(t *testing.T, sk1 string, sk2 string, conversationKey string) bool {
	var (
		sendPrivkey *secp256k1.PrivateKey
		recvPubkey  *secp256k1.PublicKey
		ok          bool
		err         error
	)
	if decoded, err := hex.DecodeString(sk1); err == nil {
		sendPrivkey = secp256k1.PrivKeyFromBytes(decoded)
	}
	if ok = assert.NoErrorf(t, err, "hex decode failed for sk1: %v", err); !ok {
		return false
	}
	if decoded, err := hex.DecodeString(sk2); err == nil {
		recvPubkey = secp256k1.PrivKeyFromBytes(decoded).PubKey()
	}
	if ok = assert.NoErrorf(t, err, "hex decode failed for sk2: %v", err); !ok {
		return false
	}
	return assertConversationKeyGeneration(t, sendPrivkey, recvPubkey, conversationKey)
}

func assertConversationKeyGenerationPub(t *testing.T, sk1 string, pub2 string, conversationKey string) bool {
	var (
		sendPrivkey *secp256k1.PrivateKey
		recvPubkey  *secp256k1.PublicKey
		ok          bool
		err         error
	)
	if decoded, err := hex.DecodeString(sk1); err == nil {
		sendPrivkey = secp256k1.PrivKeyFromBytes(decoded)
	}
	if ok = assert.NoErrorf(t, err, "hex decode failed for sk1: %v", err); !ok {
		return false
	}
	if decoded, err := hex.DecodeString("02" + pub2); err == nil {
		recvPubkey, err = secp256k1.ParsePubKey(decoded)
		if ok = assert.NoErrorf(t, err, "parse pubkey failed: %v", err); !ok {
			return false
		}
	}
	if ok = assert.NoErrorf(t, err, "hex decode failed for pub2: %v", err); !ok {
		return false
	}
	return assertConversationKeyGeneration(t, sendPrivkey, recvPubkey, conversationKey)
}

func TestCryptPriv001(t *testing.T) {
	assertCryptPriv(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"a",
		"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYNpT9ESckRbRUY7bUF5P+1rObpA4BNoksAUQ8myMDd9/37W/J2YHvBpRjvy9uC0+ovbpLc0WLaMFieqAMdIYqR14",
	)
}

func TestCryptPriv002(t *testing.T) {
	assertCryptPriv(t,
		"0000000000000000000000000000000000000000000000000000000000000002",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		"f00000000000000000000000000000f00000000000000000000000000000000f",
		"🍕🫃",
		"AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPKY68BwdF7PIT205jBoaZHSs7OMpKsULW5F5ClOJWiy6XjZy7s2v85KugYmbBKgEC2LytbXbxkr7Jpgfk529K3/pP",
	)
}

func TestCryptPriv003(t *testing.T) {
	assertCryptPriv(t,
		"5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a",
		"4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d",
		"94da47d851b9c1ed33b3b72f35434f56aa608d60e573e9c295f568011f4f50a4",
		"b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b",
		"表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀",
		"ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7yuU7XwJ8wCYUrq4aXX86HLnkMx7fPFvNeMk0uek9ma01magfEBIf+vJvZdWKiv48eUu9Cv31plAJsH6kSIsGc5TVYBYipkrQUNRxxJA15QT+uCURF96v3XuSS0k2Pf108AI=",
	)
}

func TestCryptPriv004(t *testing.T) {
	assertCryptPriv(t,
		"8f40e50a84a7462e2b8d24c28898ef1f23359fff50d8c509e6fb7ce06e142f9c",
		"b9b0a1e9cc20100c5faa3bbe2777303d25950616c4c6a3fa2e3e046f936ec2ba",
		"ab99c122d4586cdd5c813058aa543d0e7233545dbf6874fc34a3d8d9a18fbbc3",
		"b20989adc3ddc41cd2c435952c0d59a91315d8c5218d5040573fc3749543acaf",
		"ability🤝的 ȺȾ",
		"ArIJia3D3cQc0sQ1lSwNWakTFdjFIY1QQFc/w3SVQ6yvPSc+7YCIFTmGk5OLuh1nhl6TvID7sGKLFUCWRW1eRfV/0a7sT46N3nTQzD7IE67zLWrYqGnE+0DDNz6sJ4hAaFrT",
	)
}

func TestCryptPriv005(t *testing.T) {
	assertCryptPriv(t,
		"875adb475056aec0b4809bd2db9aa00cff53a649e7b59d8edcbf4e6330b0995c",
		"9c05781112d5b0a2a7148a222e50e0bd891d6b60c5483f03456e982185944aae",
		"a449f2a85c6d3db0f44c64554a05d11a3c0988d645e4b4b2592072f63662f422",
		"8d4442713eb9d4791175cb040d98d6fc5be8864d6ec2f89cf0895a2b2b72d1b1",
		"pepper👀їжак",
		"Ao1EQnE+udR5EXXLBA2Y1vxb6IZNbsL4nPCJWisrctGx1TkkMfiHJxEeSdQ/4Rlaghn0okDCNYLihBsHrDzBsNRC27APmH9mmZcpcg66Mb0exH9V5/lLBWdQW+fcY9GpvXv0",
	)
}

func TestCryptPriv006(t *testing.T) {
	assertCryptPriv(t,
		"eba1687cab6a3101bfc68fd70f214aa4cc059e9ec1b79fdb9ad0a0a4e259829f",
		"dff20d262bef9dfd94666548f556393085e6ea421c8af86e9d333fa8747e94b3",
		"decde9938ffcb14fa7ff300105eb1bf239469af9baf376e69755b9070ae48c47",
		"2180b52ae645fcf9f5080d81b1f0b5d6f2cd77ff3c986882bb549158462f3407",
		"( ͡° ͜ʖ ͡°)",
		"AiGAtSrmRfz59QgNgbHwtdbyzXf/PJhogrtUkVhGLzQHiR8Hljs6Nl/XsNDAmCz6U1Z3NUGhbCtczc3wXXxDzFkjjMimxsf/74OEzu7LphUadM9iSWvVKPrNXY7lTD0B2muz",
	)
}

func TestCryptPriv007(t *testing.T) {
	assertCryptPriv(t,
		"d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
		"b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"e4cd5f7ce4eea024bc71b17ad456a986a74ac426c2c62b0a15eb5c5c8f888b68",
		"مُنَاقَشَةُ سُبُلِ اِسْتِخْدَامِ اللُّغَةِ فِي النُّظُمِ الْقَائِمَةِ وَفِيم يَخُصَّ التَّطْبِيقَاتُ الْحاسُوبِيَّةُ،",
		"AuTNX3zk7qAkvHGxetRWqYanSsQmwsYrChXrXFyPiItohfde4vHVRHUupr+Glh9JW4f9EY+w795hvRZbixs0EQgDZ7zwLlymVQI3NNvMqvemQzHUA1I5+9gSu8XSMwX9gDCUAjUJtntCkRt9+tjdy2Wa2ZrDYqCvgirvzbJTIC69Ve3YbKuiTQCKtVi0PA5ZLqVmnkHPIqfPqDOGj/a3dvJVzGSgeijcIpjuEgFF54uirrWvIWmTBDeTA+tlQzJHpB2wQnUndd2gLDb8+eKFUZPBifshD3WmgWxv8wRv6k3DeWuWEZQ70Z+YDpgpeOzuzHj0MDBwMAlY8Qq86Rx6pxY76PLDDfHh3rE2CHJEKl2MhDj7pGXao2o633vSRd9ueG8W",
	)
}

func TestCryptPriv008(t *testing.T) {
	assertCryptPriv(t,
		"d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
		"b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"38d1ca0abef9e5f564e89761a86cee04574b6825d3ef2063b10ad75899e4b023",
		"الكل في المجمو عة (5)",
		"AjjRygq++eX1ZOiXYahs7gRXS2gl0+8gY7EK11iZ5LAjTHmhdBC3meTY4A7Lv8s8B86MnmlUBJ8ebzwxFQzDyVCcdSbWFaKe0gigEBdXew7TjrjH8BCpAbtYjoa4YHa8GNjj7zH314ApVnwoByHdLHLB9Vr6VdzkxcJgA6oL4MAsRLg=",
	)
}

func TestCryptPriv009(t *testing.T) {
	assertCryptPriv(t,
		"d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
		"b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"4f1a31909f3483a9e69c8549a55bbc9af25fa5bbecf7bd32d9896f83ef2e12e0",
		"𝖑𝖆𝖟𝖞 社會科學院語學研究所",
		"Ak8aMZCfNIOp5pyFSaVbvJryX6W77Pe9MtmJb4PvLhLg/25Q5uBC88jl5ghtEREXX6o4QijPzM0uwmkeQ54/6aIqUyzGNVdryWKZ0mee2lmVVWhU+26X6XGFQ5DGRn+1v0POsFUCZ/REh35+beBNHnyvjxD/rbrMfhP2Blc8X5m8Xvk=",
	)
}

func TestCryptPriv010(t *testing.T) {
	assertCryptPriv(t,
		"d5633530f5bcfebceb5584cfbbf718a30df0751b729dd9a789b9f30c0587d74e",
		"b74e6a341fb134127272b795a08b59250e5fa45a82a2eb4095e4ce9ed5f5e214",
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"a3e219242d85465e70adcd640b564b3feff57d2ef8745d5e7a0663b2dccceb54",
		"🙈 🙉 🙊 0️⃣ 1️⃣ 2️⃣ 3️⃣ 4️⃣ 5️⃣ 6️⃣ 7️⃣ 8️⃣ 9️⃣ 🔟 Powerلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ冗",
		"AqPiGSQthUZecK3NZAtWSz/v9X0u+HRdXnoGY7LczOtU9bUC2ji2A2udRI2VCEQZ7IAmYRRgxodBtd5Yi/5htCUczf1jLHxIt9AhVAZLKuRgbWOuEMq5RBybkxPsSeAkxzXVOlWHZ1Febq5ogkjqY/6Xj8CwwmaZxfbx+d1BKKO3Wa+IFuXwuVAZa1Xo+fan+skyf+2R5QSj10QGAnGO7odAu/iZ9A28eMoSNeXsdxqy1+PRt5Zk4i019xmf7C4PDGSzgFZSvQ2EzusJN5WcsnRFmF1L5rXpX1AYo8HusOpWcGf9PjmFbO+8spUkX1W/T21GRm4o7dro1Y6ycgGOA9BsiQ==",
	)
}

func TestCryptPub001(t *testing.T) {
	assertCryptPub(t,
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"7a1ccf5ce5a08e380f590de0c02776623b85a61ae67cfb6a017317e505b7cb51",
		"a000000000000000000000000000000000000000000000000000000000000001",
		"⁰⁴⁵₀₁₂",
		"AqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB2+xmGnjIMPMqqJGmjdYAYZUDUyEEUO3/evHUaO40LePeR91VlMVZ7I+nKJPkaUiKZ3cQiQnA86Uwti2IxepmzOFN",
	)
}

func TestCryptPub002(t *testing.T) {
	assertCryptPub(t,
		"0000000000000000000000000000000000000000000000000000000000000002",
		"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb",
		"aa971537d741089885a0b48f2730a125e15b36033d089d4537a4e1204e76b39e",
		"b000000000000000000000000000000000000000000000000000000000000002",
		"A Peer-to-Peer Electronic Cash System",
		"ArAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACyuqG6RycuPyDPtwxzTcuMQu+is3N5XuWTlvCjligVaVBRydexaylXbsX592MEd3/Jt13BNL/GlpYpGDvLS4Tt/+2s9FX/16e/RDc+czdwXglc4DdSHiq+O06BvvXYfEQOPw=",
	)
}

func TestCryptPub003(t *testing.T) {
	assertCryptPub(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. Digital signatures provide part of the solution, but the main benefits are lost if a trusted third party is still required to prevent double-spending.",
		"Anm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYb9wHyKevpe7ohJ6OkpceFcb0pySY8TLGwT7Q3zWNDKxc9blXanxKborEXkQH8xNaB2ViJfgxpkutbwbYd0Grix34xzaZBASufdsNm7R768t51tI6sdS0nms6kWLVJpEGu6Ke4Bldv4StJtWBLaTcgsgN+4WxDbBhC/nhwjEQiBBbbmUrPWjaVZXjl8dzzPrYtkSoeBNJs/UNvDwym4+qrmhv4ASTvVflpZgLlSe4seqeu6dWoRqn8uRHZQnPs+XhqwbdCHpeKGB3AfGBykZY0RIr0tjarWdXNasGbIhGM3GiLasioJeabAZw0plCevDkKpZYDaNfMJdzqFVJ8UXRIpvDpQad0SOm8lLum/aBzUpLqTjr3RvSlhYdbuODpd9pR5K60k4L2N8nrPtBv08wlilQg2ymwQgKVE6ipxIzzKMetn8+f0nQ9bHjWFJqxetSuMzzArTUQl9c4q/DwZmCBhI2",
	)
}

func TestCryptFail001(t *testing.T) {
	assertDecryptFail(t,
		"2573d1e9b9ac5de5d570f652cbb9e8d4f235e3d3d334181448e87c417f374e83",
		"8348c2d35549098706e5bab7966d9a9c72fbf6554e918f41c2b6cb275f79ec13",
		"8673ec68393a997bfad7eab8661461daf8b3931b7e885d78312a3fb7fe17f41a",
		"##Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbOsrsqIEybscEwg5rnI/Cx03mDSmeweOLKD7dw5BDZQDxXSlCwX1LIcTJEZaJPTz98Ftu0zSE0d93ED7OtdlvNeZx",
		"unknown version",
	)
}

func TestCryptFail002(t *testing.T) {
	assertDecryptFail(t,
		"11063318c5cb3cd9cafcced42b4db5ea02ec976ed995962d2bc1fa1e9b52e29f",
		"5c49873b6eac3dd363325250cc55d5dd4c7ce9a885134580405736d83506bb74",
		"e2aad10de00913088e5cb0f73fa526a6a17e95763cc5b2a127022f5ea5a73445",
		"AK1AjUvoYW3IS7C/BGRUoqEC7ayTfDUgnEPNeWTF/reBA4fZmoHrtrz5I5pCHuwWZ22qqL/Xt1VidEZGMLds0yaJ5VwUbeEifEJlPICOFt1ssZJxCUf43HvRwCVTFskbhSMh",
		"unknown version",
	)
}

func TestCryptFail003(t *testing.T) {
	assertDecryptFail(t,
		"2573d1e9b9ac5de5d570f652cbb9e8d4f235e3d3d334181448e87c417f374e83",
		"8348c2d35549098706e5bab7966d9a9c72fbf6554e918f41c2b6cb275f79ec13",
		"8673ec68393a997bfad7eab8661461daf8b3931b7e885d78312a3fb7fe17f41a",
		"Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbOsrsqIEybscEwg5rnI/Cx03mDSmeweOLKD,7dw5BDZQDxXSlCwX1LIcTJEZaJPTz98Ftu0zSE0d93ED7OtdlvNeZx",
		"invalid base64",
	)
}

func TestCryptFail004(t *testing.T) {
	assertDecryptFail(t,
		"5a2f39347fed3883c9fe05868a8f6156a292c45f606bc610495fcc020ed158f7",
		"775bbfeba58d07f9d1fbb862e306ac780f39e5418043dadb547c7b5900245e71",
		"2e70c0a1cde884b88392458ca86148d859b273a5695ede5bbe41f731d7d88ffd",
		"Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholdUejFZPARM22IvOqp1U/UmFSkeSyTBYbbwy5ykmi+mKiEcWL+nVmTOf28MMiC+rTpZys/8p1hqQFpn+XWZRPrVay",
		"invalid hmac",
	)
}

func TestCryptFail005(t *testing.T) {
	assertDecryptFail(t,
		"067eda13c4a36090ad28a7a183e9df611186ca01f63cb30fcdfa615ebfd6fb6d",
		"32c1ece2c5dd2160ad03b243f50eff12db605b86ac92da47eacc78144bf0cdd3",
		"a808915e31afc5b853d654d2519632dac7298ee2ecddc11695b8eba925935c2a",
		"AmWxSwuUmqp9UsQX63U7OQ6K1thLI69L7G2b+j4DoIr0U0P/M1/oKm95z8qz6Kg0zQawLzwk3DskvWA2drXP4zK+tzHpKvWq0KOdx5MdypboSQsP4NXfhh2KoUffjkyIOiMA",
		"invalid hmac",
	)
}

func TestCryptFail006(t *testing.T) {
	assertDecryptFail(t,
		"3e7be560fb9f8c965c48953dbd00411d48577e200cf00d7cc427e49d0e8d9c01",
		"e539e5fee58a337307e2a937ee9a7561b45876fb5df405c5e7be3ee564b239cc",
		"6ee3efc4255e3b8270e5dd3f7dc7f6b60878cda6218c8df34a3261cd48744931",
		"Anq2XbuLvCuONcr7V0UxTh8FAyWoZNEdBHXvdbNmDZHBu7F9m36yBd58mVUBB5ktBTOJREDaQT1KAyPmZidP+IRea1lNw5YAEK7+pbnpfCw8CD0i2n8Pf2IDWlKDhLiVvatw",
		"invalid padding",
	)
}

func TestCryptFail007(t *testing.T) {
	assertDecryptFail(t,
		"c22e1d4de967aa39dc143354d8f596cec1d7c912c3140831fff2976ce3e387c1",
		"4e405be192677a2da95ffc733950777213bf880cf7c3b084eeb6f3fe5bd43705",
		"1675a773dbf6fbcbef6a293004a4504b6c856978be738b10584b0269d437c8d1",
		"An1Cg+O1TIhdav7ogfSOYvCj9dep4ctxzKtZSniCw5MwhT0hvSnF9Xjp9Lml792qtNbmAVvR6laukTe9eYEjeWPpZFxtkVpYTbbL9wDKFeplDMKsUKVa+roSeSvv0ela9seDVl2Sfso=",
		"invalid padding",
	)

}

func TestCryptFail008(t *testing.T) {
	assertDecryptFail(t,
		"be1edab14c5912e5c59084f197f0945242e969c363096cccb59af8898815096f",
		"9eaf0775d971e4941c97189232542e1daefcdb7dddafc39bcea2520217710ba2",
		"1741a44c052d5ae363c7845441f73d2b6c28d9bfb3006190012bba12eb4c774b",
		"Am+f1yZnwnOs0jymZTcRpwhDRHTdnrFcPtsBzpqVdD6bL9HUMo3Mjkz4bjQo/FJF2LWHmaCr9Byc3hU9D7we+EkNBWenBHasT1G52fZk9r3NKeOC1hLezNwBLr7XXiULh+NbMBDtJh9/aQh1uZ9EpAfeISOzbZXwYwf0P5M85g9XER8hZ2fgJDLb4qMOuQRG6CrPezhr357nS3UHwPC2qHo3uKACxhE+2td+965yDcvMTx4KYTQg1zNhd7PA5v/WPnWeq2B623yLxlevUuo/OvXplFho3QVy7s5QZVop6qV2g2/l/SIsvD0HIcv3V35sywOCBR0K4VHgduFqkx/LEF3NGgAbjONXQHX8ZKushsEeR4TxlFoRSovAyYjhWolz+Ok3KJL2Ertds3H+M/Bdl2WnZGT0IbjZjn3DS+b1Ke0R0X4Onww2ZG3+7o6ncIwTc+lh1O7YQn00V0HJ+EIp03heKV2zWdVSC615By/+Yt9KAiV56n5+02GAuNqA",
		"invalid padding",
	)
}

func TestConversationKey001(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
		"c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
		"3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1",
	)
}

func TestConversationKey002(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
		"03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
		"4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b",
	)
}

func TestConversationKey003(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311",
		"aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1",
		"9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7",
	)
}

func TestConversationKey004(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"86ae5ac8034eb2542ce23ec2f84375655dab7f836836bbd3c54cefe9fdc9c19f",
		"59f90272378089d73f1339710c02e2be6db584e9cdbe86eed3578f0c67c23585",
		"19f934aafd3324e8415299b64df42049afaa051c71c98d0aa10e1081f2e3e2ba",
	)
}

func TestConversationKey005(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"2528c287fe822421bc0dc4c3615878eb98e8a8c31657616d08b29c00ce209e34",
		"f66ea16104c01a1c532e03f166c5370a22a5505753005a566366097150c6df60",
		"c833bbb292956c43366145326d53b955ffb5da4e4998a2d853611841903f5442",
	)
}

func TestConversationKey006(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"49808637b2d21129478041813aceb6f2c9d4929cd1303cdaf4fbdbd690905ff2",
		"74d2aab13e97827ea21baf253ad7e39b974bb2498cc747cdb168582a11847b65",
		"4bf304d3c8c4608864c0fe03890b90279328cd24a018ffa9eb8f8ccec06b505d",
	)
}

func TestConversationKey007(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"af67c382106242c5baabf856efdc0629cc1c5b4061f85b8ceaba52aa7e4b4082",
		"bdaf0001d63e7ec994fad736eab178ee3c2d7cfc925ae29f37d19224486db57b",
		"a3a575dd66d45e9379904047ebfb9a7873c471687d0535db00ef2daa24b391db",
	)
}

func TestConversationKey008(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"0e44e2d1db3c1717b05ffa0f08d102a09c554a1cbbf678ab158b259a44e682f1",
		"1ffa76c5cc7a836af6914b840483726207cb750889753d7499fb8b76aa8fe0de",
		"a39970a667b7f861f100e3827f4adbf6f464e2697686fe1a81aeda817d6b8bdf",
	)
}

func TestConversationKey009(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"5fc0070dbd0666dbddc21d788db04050b86ed8b456b080794c2a0c8e33287bb6",
		"31990752f296dd22e146c9e6f152a269d84b241cc95bb3ff8ec341628a54caf0",
		"72c21075f4b2349ce01a3e604e02a9ab9f07e35dd07eff746de348b4f3c6365e",
	)
}

func TestConversationKey010(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"1b7de0d64d9b12ddbb52ef217a3a7c47c4362ce7ea837d760dad58ab313cba64",
		"24383541dd8083b93d144b431679d70ef4eec10c98fceef1eff08b1d81d4b065",
		"dd152a76b44e63d1afd4dfff0785fa07b3e494a9e8401aba31ff925caeb8f5b1",
	)
}

func TestConversationKey011(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"df2f560e213ca5fb33b9ecde771c7c0cbd30f1cf43c2c24de54480069d9ab0af",
		"eeea26e552fc8b5e377acaa03e47daa2d7b0c787fac1e0774c9504d9094c430e",
		"770519e803b80f411c34aef59c3ca018608842ebf53909c48d35250bd9323af6",
	)
}

func TestConversationKey012(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"cffff919fcc07b8003fdc63bc8a00c0f5dc81022c1c927c62c597352190d95b9",
		"eb5c3cca1a968e26684e5b0eb733aecfc844f95a09ac4e126a9e58a4e4902f92",
		"46a14ee7e80e439ec75c66f04ad824b53a632b8409a29bbb7c192e43c00bb795",
	)
}

func TestConversationKey013(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"64ba5a685e443e881e9094647ddd32db14444bb21aa7986beeba3d1c4673ba0a",
		"50e6a4339fac1f3bf86f2401dd797af43ad45bbf58e0801a7877a3984c77c3c4",
		"968b9dbbfcede1664a4ca35a5d3379c064736e87aafbf0b5d114dff710b8a946",
	)
}

func TestConversationKey014(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"dd0c31ccce4ec8083f9b75dbf23cc2878e6d1b6baa17713841a2428f69dee91a",
		"b483e84c1339812bed25be55cff959778dfc6edde97ccd9e3649f442472c091b",
		"09024503c7bde07eb7865505891c1ea672bf2d9e25e18dd7a7cea6c69bf44b5d",
	)
}

func TestConversationKey015(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"af71313b0d95c41e968a172b33ba5ebd19d06cdf8a7a98df80ecf7af4f6f0358",
		"2a5c25266695b461ee2af927a6c44a3c598b8095b0557e9bd7f787067435bc7c",
		"fe5155b27c1c4b4e92a933edae23726a04802a7cc354a77ac273c85aa3c97a92",
	)
}

func TestConversationKey016(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"6636e8a389f75fe068a03b3edb3ea4a785e2768e3f73f48ffb1fc5e7cb7289dc",
		"514eb2064224b6a5829ea21b6e8f7d3ea15ff8e70e8555010f649eb6e09aec70",
		"ff7afacd4d1a6856d37ca5b546890e46e922b508639214991cf8048ddbe9745c",
	)
}

func TestConversationKey017(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"94b212f02a3cfb8ad147d52941d3f1dbe1753804458e6645af92c7b2ea791caa",
		"f0cac333231367a04b652a77ab4f8d658b94e86b5a8a0c472c5c7b0d4c6a40cc",
		"e292eaf873addfed0a457c6bd16c8effde33d6664265697f69f420ab16f6669b",
	)
}

func TestConversationKey018(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"aa61f9734e69ae88e5d4ced5aae881c96f0d7f16cca603d3bed9eec391136da6",
		"4303e5360a884c360221de8606b72dd316da49a37fe51e17ada4f35f671620a6",
		"8e7d44fd4767456df1fb61f134092a52fcd6836ebab3b00766e16732683ed848",
	)
}

func TestConversationKey019(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"5e914bdac54f3f8e2cba94ee898b33240019297b69e96e70c8a495943a72fc98",
		"5bd097924f606695c59f18ff8fd53c174adbafaaa71b3c0b4144a3e0a474b198",
		"f5a0aecf2984bf923c8cd5e7bb8be262d1a8353cb93959434b943a07cf5644bc",
	)
}

func TestConversationKey020(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"8b275067add6312ddee064bcdbeb9d17e88aa1df36f430b2cea5cc0413d8278a",
		"65bbbfca819c90c7579f7a82b750a18c858db1afbec8f35b3c1e0e7b5588e9b8",
		"2c565e7027eb46038c2263563d7af681697107e975e9914b799d425effd248d6",
	)
}

func TestConversationKey021(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"1ac848de312285f85e0f7ec208aac20142a1f453402af9b34ec2ec7a1f9c96fc",
		"45f7318fe96034d23ee3ddc25b77f275cc1dd329664dd51b89f89c4963868e41",
		"b56e970e5057a8fd929f8aad9248176b9af87819a708d9ddd56e41d1aec74088",
	)
}

func TestConversationKey022(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"295a1cf621de401783d29d0e89036aa1c62d13d9ad307161b4ceb535ba1b40e6",
		"840115ddc7f1034d3b21d8e2103f6cb5ab0b63cf613f4ea6e61ae3d016715cdd",
		"b4ee9c0b9b9fef88975773394f0a6f981ca016076143a1bb575b9ff46e804753",
	)
}

func TestConversationKey023(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"a28eed0fe977893856ab9667e06ace39f03abbcdb845c329a1981be438ba565d",
		"b0f38b950a5013eba5ab4237f9ed29204a59f3625c71b7e210fec565edfa288c",
		"9d3a802b45bc5aeeb3b303e8e18a92ddd353375710a31600d7f5fff8f3a7285b",
	)
}

func TestConversationKey024(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"7ab65af72a478c05f5c651bdc4876c74b63d20d04cdbf71741e46978797cd5a4",
		"f1112159161b568a9cb8c9dd6430b526c4204bcc8ce07464b0845b04c041beda",
		"943884cddaca5a3fef355e9e7f08a3019b0b66aa63ec90278b0f9fdb64821e79",
	)
}

func TestConversationKey025(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"95c79a7b75ba40f2229e85756884c138916f9d103fc8f18acc0877a7cceac9fe",
		"cad76bcbd31ca7bbda184d20cc42f725ed0bb105b13580c41330e03023f0ffb3",
		"81c0832a669eea13b4247c40be51ccfd15bb63fcd1bba5b4530ce0e2632f301b",
	)
}

func TestConversationKey026(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"baf55cc2febd4d980b4b393972dfc1acf49541e336b56d33d429bce44fa12ec9",
		"0c31cf87fe565766089b64b39460ebbfdedd4a2bc8379be73ad3c0718c912e18",
		"37e2344da9ecdf60ae2205d81e89d34b280b0a3f111171af7e4391ded93b8ea6",
	)
}

func TestConversationKey027(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"6eeec45acd2ed31693c5256026abf9f072f01c4abb61f51cf64e6956b6dc8907",
		"e501b34ed11f13d816748c0369b0c728e540df3755bab59ed3327339e16ff828",
		"afaa141b522ddb27bb880d768903a7f618bb8b6357728cae7fb03af639b946e6",
	)
}

func TestConversationKey028(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"261a076a9702af1647fb343c55b3f9a4f1096273002287df0015ba81ce5294df",
		"b2777c863878893ae100fb740c8fab4bebd2bf7be78c761a75593670380a6112",
		"76f8d2853de0734e51189ced523c09427c3e46338b9522cd6f74ef5e5b475c74",
	)
}

func TestConversationKey029(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"ed3ec71ca406552ea41faec53e19f44b8f90575eda4b7e96380f9cc73c26d6f3",
		"86425951e61f94b62e20cae24184b42e8e17afcf55bafa58645efd0172624fae",
		"f7ffc520a3a0e9e9b3c0967325c9bf12707f8e7a03f28b6cd69ae92cf33f7036",
	)
}

func TestConversationKey030(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"5a788fc43378d1303ac78639c59a58cb88b08b3859df33193e63a5a3801c722e",
		"a8cba2f87657d229db69bee07850fd6f7a2ed070171a06d006ec3a8ac562cf70",
		"7d705a27feeedf78b5c07283362f8e361760d3e9f78adab83e3ae5ce7aeb6409",
	)
}

func TestConversationKey031(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"63bffa986e382b0ac8ccc1aa93d18a7aa445116478be6f2453bad1f2d3af2344",
		"b895c70a83e782c1cf84af558d1038e6b211c6f84ede60408f519a293201031d",
		"3a3b8f00d4987fc6711d9be64d9c59cf9a709c6c6481c2cde404bcc7a28f174e",
	)
}

func TestConversationKey032(t *testing.T) {
	assertConversationKeyGenerationPub(t,
		"e4a8bcacbf445fd3721792b939ff58e691cdcba6a8ba67ac3467b45567a03e5c",
		"b54053189e8c9252c6950059c783edb10675d06d20c7b342f73ec9fa6ed39c9d",
		"7b3933b4ef8189d347169c7955589fc1cfc01da5239591a08a183ff6694c44ad",
	)
}

func TestConversationKey033(t *testing.T) {
	// sec1 = n-2, pub2: random, 0x02
	assertConversationKeyGenerationPub(t,
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"8b6392dbf2ec6a2b2d5b1477fc2be84d63ef254b667cadd31bd3f444c44ae6ba",
	)
}

func TestConversationKey034(t *testing.T) {
	// sec1 = 2, pub2: rand
	assertConversationKeyGenerationPub(t,
		"0000000000000000000000000000000000000000000000000000000000000002",
		"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb",
		"be234f46f60a250bef52a5ee34c758800c4ca8e5030bf4cc1a31d37ba2104d43",
	)
}

func TestConversationKey035(t *testing.T) {
	// sec1 == pub2
	assertConversationKeyGenerationPub(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e",
	)
}
