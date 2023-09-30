package nip44_test

import (
	"encoding/hex"
	"testing"

	"git.ekzyis.com/ekzyis/nip44"
	"github.com/stretchr/testify/assert"
)

func assertCrypt(t *testing.T, key string, salt string, plaintext string, expected string) {
	var (
		k         []byte
		s         []byte
		actual    string
		decrypted string
		err       error
		ok        bool
	)
	k, err = hex.DecodeString(key)
	if ok = assert.NoErrorf(t, err, "hex decode failed for key: %v", err); !ok {
		return
	}
	s, err = hex.DecodeString(salt)
	if ok = assert.NoErrorf(t, err, "hex decode failed for salt: %v", err); !ok {
		return
	}
	actual, err = nip44.Encrypt(k, plaintext, &nip44.EncryptOptions{Salt: s})
	if ok = assert.NoError(t, err, "encryption failed: %v", err); !ok {
		return
	}
	if ok = assert.Equalf(t, expected, actual, "wrong encryption"); !ok {
		return
	}
	decrypted, err = nip44.Decrypt(k, expected)
	if ok = assert.NoErrorf(t, err, "decryption failed: %v", err); !ok {
		return
	}
	assert.Equal(t, decrypted, plaintext, "wrong decryption")
}

func assertDecryptFail(t *testing.T, key string, ciphertext string, msg string) {
	var (
		k   []byte
		err error
		ok  bool
	)
	k, err = hex.DecodeString(key)
	if ok = assert.NoErrorf(t, err, "hex decode failed for key: %v", err); !ok {
		return
	}
	_, err = nip44.Decrypt(k, ciphertext)
	assert.ErrorContains(t, err, msg)
}

func TestCrypt001(t *testing.T) {
	assertCrypt(t,
		"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"a",
		"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYNpT9ESckRbRUY7bUF5P+1rObpA4BNoksAUQ8myMDd9/37W/J2YHvBpRjvy9uC0+ovbpLc0WLaMFieqAMdIYqR14",
	)
}

func TestCrypt002(t *testing.T) {
	assertCrypt(t,
		"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		"f00000000000000000000000000000f00000000000000000000000000000000f",
		"🍕🫃",
		"AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPKY68BwdF7PIT205jBoaZHSs7OMpKsULW5F5ClOJWiy6XjZy7s2v85KugYmbBKgEC2LytbXbxkr7Jpgfk529K3/pP",
	)
}

func TestCrypt003(t *testing.T) {
	assertCrypt(t,
		"94da47d851b9c1ed33b3b72f35434f56aa608d60e573e9c295f568011f4f50a4",
		"b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b",
		"表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀",
		"ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7yuU7XwJ8wCYUrq4aXX86HLnkMx7fPFvNeMk0uek9ma01magfEBIf+vJvZdWKiv48eUu9Cv31plAJsH6kSIsGc5TVYBYipkrQUNRxxJA15QT+uCURF96v3XuSS0k2Pf108AI=",
	)
}

func TestCrypt004(t *testing.T) {
	assertCrypt(t,
		"ab99c122d4586cdd5c813058aa543d0e7233545dbf6874fc34a3d8d9a18fbbc3",
		"b20989adc3ddc41cd2c435952c0d59a91315d8c5218d5040573fc3749543acaf",
		"ability🤝的 ȺȾ",
		"ArIJia3D3cQc0sQ1lSwNWakTFdjFIY1QQFc/w3SVQ6yvPSc+7YCIFTmGk5OLuh1nhl6TvID7sGKLFUCWRW1eRfV/0a7sT46N3nTQzD7IE67zLWrYqGnE+0DDNz6sJ4hAaFrT",
	)
}

func TestCrypt005(t *testing.T) {
	assertCrypt(t,
		"a449f2a85c6d3db0f44c64554a05d11a3c0988d645e4b4b2592072f63662f422",
		"8d4442713eb9d4791175cb040d98d6fc5be8864d6ec2f89cf0895a2b2b72d1b1",
		"pepper👀їжак",
		"Ao1EQnE+udR5EXXLBA2Y1vxb6IZNbsL4nPCJWisrctGx1TkkMfiHJxEeSdQ/4Rlaghn0okDCNYLihBsHrDzBsNRC27APmH9mmZcpcg66Mb0exH9V5/lLBWdQW+fcY9GpvXv0",
	)
}

func TestCrypt006(t *testing.T) {
	assertCrypt(t,
		"decde9938ffcb14fa7ff300105eb1bf239469af9baf376e69755b9070ae48c47",
		"2180b52ae645fcf9f5080d81b1f0b5d6f2cd77ff3c986882bb549158462f3407",
		"( ͡° ͜ʖ ͡°)",
		"AiGAtSrmRfz59QgNgbHwtdbyzXf/PJhogrtUkVhGLzQHiR8Hljs6Nl/XsNDAmCz6U1Z3NUGhbCtczc3wXXxDzFkjjMimxsf/74OEzu7LphUadM9iSWvVKPrNXY7lTD0B2muz",
	)
}

func TestCrypt007(t *testing.T) {
	assertCrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"e4cd5f7ce4eea024bc71b17ad456a986a74ac426c2c62b0a15eb5c5c8f888b68",
		"مُنَاقَشَةُ سُبُلِ اِسْتِخْدَامِ اللُّغَةِ فِي النُّظُمِ الْقَائِمَةِ وَفِيم يَخُصَّ التَّطْبِيقَاتُ الْحاسُوبِيَّةُ،",
		"AuTNX3zk7qAkvHGxetRWqYanSsQmwsYrChXrXFyPiItohfde4vHVRHUupr+Glh9JW4f9EY+w795hvRZbixs0EQgDZ7zwLlymVQI3NNvMqvemQzHUA1I5+9gSu8XSMwX9gDCUAjUJtntCkRt9+tjdy2Wa2ZrDYqCvgirvzbJTIC69Ve3YbKuiTQCKtVi0PA5ZLqVmnkHPIqfPqDOGj/a3dvJVzGSgeijcIpjuEgFF54uirrWvIWmTBDeTA+tlQzJHpB2wQnUndd2gLDb8+eKFUZPBifshD3WmgWxv8wRv6k3DeWuWEZQ70Z+YDpgpeOzuzHj0MDBwMAlY8Qq86Rx6pxY76PLDDfHh3rE2CHJEKl2MhDj7pGXao2o633vSRd9ueG8W",
	)
}

func TestCrypt008(t *testing.T) {
	assertCrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"38d1ca0abef9e5f564e89761a86cee04574b6825d3ef2063b10ad75899e4b023",
		"الكل في المجمو عة (5)",
		"AjjRygq++eX1ZOiXYahs7gRXS2gl0+8gY7EK11iZ5LAjTHmhdBC3meTY4A7Lv8s8B86MnmlUBJ8ebzwxFQzDyVCcdSbWFaKe0gigEBdXew7TjrjH8BCpAbtYjoa4YHa8GNjj7zH314ApVnwoByHdLHLB9Vr6VdzkxcJgA6oL4MAsRLg=",
	)
}

func TestCrypt009(t *testing.T) {
	assertCrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"4f1a31909f3483a9e69c8549a55bbc9af25fa5bbecf7bd32d9896f83ef2e12e0",
		"𝖑𝖆𝖟𝖞 社會科學院語學研究所",
		"Ak8aMZCfNIOp5pyFSaVbvJryX6W77Pe9MtmJb4PvLhLg/25Q5uBC88jl5ghtEREXX6o4QijPzM0uwmkeQ54/6aIqUyzGNVdryWKZ0mee2lmVVWhU+26X6XGFQ5DGRn+1v0POsFUCZ/REh35+beBNHnyvjxD/rbrMfhP2Blc8X5m8Xvk=",
	)
}

func TestCrypt010(t *testing.T) {
	assertCrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"a3e219242d85465e70adcd640b564b3feff57d2ef8745d5e7a0663b2dccceb54",
		"🙈 🙉 🙊 0️⃣ 1️⃣ 2️⃣ 3️⃣ 4️⃣ 5️⃣ 6️⃣ 7️⃣ 8️⃣ 9️⃣ 🔟 Powerلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ冗",
		"AqPiGSQthUZecK3NZAtWSz/v9X0u+HRdXnoGY7LczOtU9bUC2ji2A2udRI2VCEQZ7IAmYRRgxodBtd5Yi/5htCUczf1jLHxIt9AhVAZLKuRgbWOuEMq5RBybkxPsSeAkxzXVOlWHZ1Febq5ogkjqY/6Xj8CwwmaZxfbx+d1BKKO3Wa+IFuXwuVAZa1Xo+fan+skyf+2R5QSj10QGAnGO7odAu/iZ9A28eMoSNeXsdxqy1+PRt5Zk4i019xmf7C4PDGSzgFZSvQ2EzusJN5WcsnRFmF1L5rXpX1AYo8HusOpWcGf9PjmFbO+8spUkX1W/T21GRm4o7dro1Y6ycgGOA9BsiQ==",
	)
}

func TestCrypt011(t *testing.T) {
	assertCrypt(t,
		"7a1ccf5ce5a08e380f590de0c02776623b85a61ae67cfb6a017317e505b7cb51",
		"a000000000000000000000000000000000000000000000000000000000000001",
		"⁰⁴⁵₀₁₂",
		"AqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB2+xmGnjIMPMqqJGmjdYAYZUDUyEEUO3/evHUaO40LePeR91VlMVZ7I+nKJPkaUiKZ3cQiQnA86Uwti2IxepmzOFN",
	)
}

func TestCrypt012(t *testing.T) {
	assertCrypt(t,
		"aa971537d741089885a0b48f2730a125e15b36033d089d4537a4e1204e76b39e",
		"b000000000000000000000000000000000000000000000000000000000000002",
		"A Peer-to-Peer Electronic Cash System",
		"ArAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACyuqG6RycuPyDPtwxzTcuMQu+is3N5XuWTlvCjligVaVBRydexaylXbsX592MEd3/Jt13BNL/GlpYpGDvLS4Tt/+2s9FX/16e/RDc+czdwXglc4DdSHiq+O06BvvXYfEQOPw=",
	)
}

func TestCrypt013(t *testing.T) {
	assertCrypt(t,
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. Digital signatures provide part of the solution, but the main benefits are lost if a trusted third party is still required to prevent double-spending.",
		"Anm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYb9wHyKevpe7ohJ6OkpceFcb0pySY8TLGwT7Q3zWNDKxc9blXanxKborEXkQH8xNaB2ViJfgxpkutbwbYd0Grix34xzaZBASufdsNm7R768t51tI6sdS0nms6kWLVJpEGu6Ke4Bldv4StJtWBLaTcgsgN+4WxDbBhC/nhwjEQiBBbbmUrPWjaVZXjl8dzzPrYtkSoeBNJs/UNvDwym4+qrmhv4ASTvVflpZgLlSe4seqeu6dWoRqn8uRHZQnPs+XhqwbdCHpeKGB3AfGBykZY0RIr0tjarWdXNasGbIhGM3GiLasioJeabAZw0plCevDkKpZYDaNfMJdzqFVJ8UXRIpvDpQad0SOm8lLum/aBzUpLqTjr3RvSlhYdbuODpd9pR5K60k4L2N8nrPtBv08wlilQg2ymwQgKVE6ipxIzzKMetn8+f0nQ9bHjWFJqxetSuMzzArTUQl9c4q/DwZmCBhI2",
	)
}

func TestCryptFail001(t *testing.T) {
	assertDecryptFail(t,
		"8673ec68393a997bfad7eab8661461daf8b3931b7e885d78312a3fb7fe17f41a",
		"##Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbOsrsqIEybscEwg5rnI/Cx03mDSmeweOLKD7dw5BDZQDxXSlCwX1LIcTJEZaJPTz98Ftu0zSE0d93ED7OtdlvNeZx",
		"unknown version",
	)
}

func TestCryptFail002(t *testing.T) {
	assertDecryptFail(t,
		"e2aad10de00913088e5cb0f73fa526a6a17e95763cc5b2a127022f5ea5a73445",
		"AK1AjUvoYW3IS7C/BGRUoqEC7ayTfDUgnEPNeWTF/reBA4fZmoHrtrz5I5pCHuwWZ22qqL/Xt1VidEZGMLds0yaJ5VwUbeEifEJlPICOFt1ssZJxCUf43HvRwCVTFskbhSMh",
		"unknown version",
	)
}

func TestCryptFail003(t *testing.T) {
	assertDecryptFail(t,
		"8673ec68393a997bfad7eab8661461daf8b3931b7e885d78312a3fb7fe17f41a",
		"Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbOsrsqIEybscEwg5rnI/Cx03mDSmeweOLKD,7dw5BDZQDxXSlCwX1LIcTJEZaJPTz98Ftu0zSE0d93ED7OtdlvNeZx",
		"invalid base64",
	)
}

func TestCryptFail004(t *testing.T) {
	assertDecryptFail(t,
		"2e70c0a1cde884b88392458ca86148d859b273a5695ede5bbe41f731d7d88ffd",
		"Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholdUejFZPARM22IvOqp1U/UmFSkeSyTBYbbwy5ykmi+mKiEcWL+nVmTOf28MMiC+rTpZys/8p1hqQFpn+XWZRPrVay",
		"invalid hmac",
	)
}

func TestCryptFail005(t *testing.T) {
	assertDecryptFail(t,
		"a808915e31afc5b853d654d2519632dac7298ee2ecddc11695b8eba925935c2a",
		"AmWxSwuUmqp9UsQX63U7OQ6K1thLI69L7G2b+j4DoIr0U0P/M1/oKm95z8qz6Kg0zQawLzwk3DskvWA2drXP4zK+tzHpKvWq0KOdx5MdypboSQsP4NXfhh2KoUffjkyIOiMA",
		"invalid hmac",
	)
}

func TestCryptFail006(t *testing.T) {
	assertDecryptFail(t,
		"6ee3efc4255e3b8270e5dd3f7dc7f6b60878cda6218c8df34a3261cd48744931",
		"Anq2XbuLvCuONcr7V0UxTh8FAyWoZNEdBHXvdbNmDZHBu7F9m36yBd58mVUBB5ktBTOJREDaQT1KAyPmZidP+IRea1lNw5YAEK7+pbnpfCw8CD0i2n8Pf2IDWlKDhLiVvatw",
		"invalid padding",
	)
}

func TestCryptFail007(t *testing.T) {
	assertDecryptFail(t,
		"1675a773dbf6fbcbef6a293004a4504b6c856978be738b10584b0269d437c8d1",
		"An1Cg+O1TIhdav7ogfSOYvCj9dep4ctxzKtZSniCw5MwhT0hvSnF9Xjp9Lml792qtNbmAVvR6laukTe9eYEjeWPpZFxtkVpYTbbL9wDKFeplDMKsUKVa+roSeSvv0ela9seDVl2Sfso=",
		"invalid padding",
	)

}

func TestCryptFail008(t *testing.T) {
	assertDecryptFail(t,
		"1741a44c052d5ae363c7845441f73d2b6c28d9bfb3006190012bba12eb4c774b",
		"Am+f1yZnwnOs0jymZTcRpwhDRHTdnrFcPtsBzpqVdD6bL9HUMo3Mjkz4bjQo/FJF2LWHmaCr9Byc3hU9D7we+EkNBWenBHasT1G52fZk9r3NKeOC1hLezNwBLr7XXiULh+NbMBDtJh9/aQh1uZ9EpAfeISOzbZXwYwf0P5M85g9XER8hZ2fgJDLb4qMOuQRG6CrPezhr357nS3UHwPC2qHo3uKACxhE+2td+965yDcvMTx4KYTQg1zNhd7PA5v/WPnWeq2B623yLxlevUuo/OvXplFho3QVy7s5QZVop6qV2g2/l/SIsvD0HIcv3V35sywOCBR0K4VHgduFqkx/LEF3NGgAbjONXQHX8ZKushsEeR4TxlFoRSovAyYjhWolz+Ok3KJL2Ertds3H+M/Bdl2WnZGT0IbjZjn3DS+b1Ke0R0X4Onww2ZG3+7o6ncIwTc+lh1O7YQn00V0HJ+EIp03heKV2zWdVSC615By/+Yt9KAiV56n5+02GAuNqA",
		"invalid padding",
	)
}
