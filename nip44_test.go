package nip44_test

import (
	"encoding/hex"
	"testing"

	"git.ekzyis.com/ekzyis/nip44"
	"github.com/stretchr/testify/assert"
)

func assertEncrypt(t *testing.T, key string, salt string, plaintext string, expected string) {
	var (
		k      []byte
		s      []byte
		actual string
		err    error
	)
	if k, err = hex.DecodeString(key); err != nil {
		t.Errorf("hex decode failed for key")
	}
	if s, err = hex.DecodeString(salt); err != nil {
		t.Errorf("hex decode failed for salt")
	}
	actual, err = nip44.Encrypt(k, plaintext, &nip44.EncryptOptions{Salt: s})
	if assert.NoError(t, err) {
		assert.Equal(t, expected, actual)
	}
}

func TestEncrypt001(t *testing.T) {
	assertEncrypt(t,
		"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"a",
		"1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHTOSW6Gdkq32HWa3eYdF97ALzFK45Wcg4jeuK7zz3ye/dSEcTB08Xlr+DEgYg7J8kHQaQXZKxiarHVSMiw+vqe4lE=",
	)
}

func TestEncrypt002(t *testing.T) {
	assertEncrypt(t,
		"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		"f00000000000000000000000000000f00000000000000000000000000000000f",
		"a",
		"18AAAAAAAAAAAAAAAAAAA8AAAAAAAAAAAAAAAAAAAAA+a0vMgbnISrKRDMofXovg8VbAAhbzq+mGWJdXk8B8ghukg530TqwmeXWMP1NxGKkgMG9biGbuZO96INKNZbNRlsc0=",
	)
}

func TestEncrypt003(t *testing.T) {
	assertEncrypt(t,
		"94da47d851b9c1ed33b3b72f35434f56aa608d60e573e9c295f568011f4f50a4",
		"b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b",
		"hello",
		"1tjUjbELbIPAhu40c3/XKdd0aDMcup0KtdQ8zAQsk9zuSsVmJEDFI8g3JbPGCpjtRkbN6vQUabk5VABU/+Of5YsnPnf2sWHwrqxJAQpCNrcvYURhE8N6ozQuL4YIJoYS8dg4=",
	)
}

func TestEncrypt004(t *testing.T) {
	assertEncrypt(t,
		"ab99c122d4586cdd5c813058aa543d0e7233545dbf6874fc34a3d8d9a18fbbc3",
		"b20989adc3ddc41cd2c435952c0d59a91315d8c5218d5040573fc3749543acaf",
		"ability🤝的",
		"1sgmJrcPdxBzSxDWVLA1ZqRMV2MUhjVBAVz/DdJVDrK9lMoaMWXcf/EdinErxE6UBRilzkGL9G+tzfh1KNVU/Oc1zF2viAJHDbYFpyPvDJjv6lEsU9CPT39RrwBsGQex9w+Y=",
	)
}

func TestEncrypt005(t *testing.T) {
	assertEncrypt(t,
		"22cfa4f054bbf05d0bcf27a3ecfcb6f0e59b84f6ec6a27ba153484c0160ea3e7",
		"b19c7e24de280656ecf5c1999f1d9db9d1b4accd725c4d509d698cb58206f5a3",
		"island👀привет",
		"1sZx+JN4oBlbs9cGZnx2dudG0rM1yXE1QnWmMtYIG9aMu7jiyg6elfGEBHT8vr8/kCqKDUBpEjWVd4OeOn1IoeYaK6KKhp4eBTLiSg04m9NTxCNe6wd+Km1gbKOSSu8m6lYs=",
	)
}

func TestEncrypt006(t *testing.T) {
	assertEncrypt(t,
		"a449f2a85c6d3db0f44c64554a05d11a3c0988d645e4b4b2592072f63662f422",
		"8d4442713eb9d4791175cb040d98d6fc5be8864d6ec2f89cf0895a2b2b72d1b1",
		"pepper👀їжак",
		"1jURCcT651HkRdcsEDZjW/Fvohk1uwvic8IlaKyty0bERl5cBQxCc1p1wc1HkEBJUxQYTIxac7hLr9lD19xfyosePy2ZQamMMMpgMRlWkAxGCWDVHAcX/sB9VQW6kTGGdMmw=",
	)
}

func TestEncrypt007(t *testing.T) {
	assertEncrypt(t,
		"decde9938ffcb14fa7ff300105eb1bf239469af9baf376e69755b9070ae48c47",
		"2180b52ae645fcf9f5080d81b1f0b5d6f2cd77ff3c986882bb549158462f3407",
		"あいさつ👀pepper",
		"1IYC1KuZF/Pn1CA2BsfC11vLNd/88mGiCu1SRWEYvNAfIrYmhfhmnCoT/09aEF5Iv5ytpP83YRqh9O0ea3Tml47hl10objAvLHc36fKYDQG49OxHxUazqLDLBerxAN6HeU2A=",
	)
}

func TestEncrypt008(t *testing.T) {
	assertEncrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"e4cd5f7ce4eea024bc71b17ad456a986a74ac426c2c62b0a15eb5c5c8f888b68",
		"people💃的 people💃的 people💃的 people💃的 people💃的",
		"15M1ffOTuoCS8cbF61FaphqdKxCbCxisKFetcXI+Ii2i6Q92kxZtgNCR/yHuuxwTUG6f2EgWBkmn3IQiWNhP4Givk4ZRZ7B+XVSlpLlHR93a3DIi+LzgHms6IBfyMXtTws5a071V4AfhdfBdPHc/2Dx/luOroPlx8WKA4g48cMI5cHTpjzR/397Dwv0vzIoE0Wn7AzsiLRUjho4orHIl4YOT0",
	)
}

func TestEncrypt009(t *testing.T) {
	assertEncrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"38d1ca0abef9e5f564e89761a86cee04574b6825d3ef2063b10ad75899e4b023",
		"people💃的 people💃的 people💃的 people💃的 people💃的 people💃的",
		"1ONHKCr755fVk6JdhqGzuBFdLaCXT7yBjsQrXWJnksCPUDy+AuM/JjiOcDfb+HYyM86BhGVGbMtBJIznJqf+QyyK4br9OpnZjQktVQ5V5mQjT8UBvdoft2Mx9o0gHz1/VGltfBoS3+udaFJIt6NBF0AGMIWvi5dCzWdlVqZlRGhxMNy+hugQTJGVl0sn2WquWq/j7pEQ4IegrdOjCaEm2i76b",
	)
}

func TestEncrypt010(t *testing.T) {
	assertEncrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"4f1a31909f3483a9e69c8549a55bbc9af25fa5bbecf7bd32d9896f83ef2e12e0",
		"people💃的 people💃的 people💃的 people💃的 people💃的 people💃的 people💃的",
		"1TxoxkJ80g6nmnIVJpVu8mvJfpbvs970y2Ylvg+8uEuAiL5ShBCogVU05zdUlp0bOzfV7PXhx1IjdTEG4EWsz9SQqwwFZZNMRU9IW6jga6uuXVRBV3RharTWBZtNfJhYtwAf2K9FHxO4T8PkQ1W0PckZs6Bun0vG3qIZtkqrMqWoH/omP0ind+9kFxsqi+1k6ad8JO/Hko2y/YLrlFupRZnwe7NjEbZFZmvndPQoGA4nN37Z9/XIzk1MJyjZGphqF3AA=",
	)
}

func TestEncrypt011(t *testing.T) {
	assertEncrypt(t,
		"c6f2fde7aa00208c388f506455c31c3fa07caf8b516d43bf7514ee19edcda994",
		"a3e219242d85465e70adcd640b564b3feff57d2ef8745d5e7a0663b2dccceb54",
		"people💃的 people💃的 people💃的 people💃的 people💃的 people💃的 people💃的 people💃的",
		"1o+IZJC2FRl5wrc1kC1ZLP+/1fS74dF1eegZjstzM61SVnOdO3J0zky0Bqpp0BXKPKv58Iw088z2b8relJxw0l+ddORD60R1rMNpQfWx4EbKCU/qV40jGYny0EqX4yIIYjRwqcAieIIaaOyGTZcYVcJiRswqOBcUQCAlO6E1+wNYweMwjjrQI3G0rO2Fbng2VYCwGWP2t9T0Kd/kVMukM9DuessMRB2uuoiD2pQz1q9XrzOy3uOChNa5c9fwpuq5UCiA=",
	)
}

func TestEncrypt012(t *testing.T) {
	assertEncrypt(t, "7a1ccf5ce5a08e380f590de0c02776623b85a61ae67cfb6a017317e505b7cb51",
		"a000000000000000000000000000000000000000000000000000000000000001",
		"a",
		"1oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNT8GMeM9D/8kVHayoPPnYyIoBXoYXUEwlvwb61OtoikfwRuTI62oZ2dsD4HE/he0eCd4aIb+4gqv+3oRQGk62SF8=",
	)
}

func TestEncrypt013(t *testing.T) {
	assertEncrypt(t,
		"aa971537d741089885a0b48f2730a125e15b36033d089d4537a4e1204e76b39e",
		"b000000000000000000000000000000000000000000000000000000000000002",
		"A Peer-to-Peer Electronic Cash System",
		"1sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALmLsOQlNZ4u0Hthr0erS1GSK4kxKWVfikA7rrb1SjPSW6H9TbmtgV1qRKRzdJLn+8OQthPl1d+Ec4HZGZ04uGRTZe7wD0+0NCcjLP+eZ+fOZyxpQIG9bz47JHlOLDbefLWiQ==",
	)
}
func TestEncrypt014(t *testing.T) {
	assertEncrypt(t,
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. Digital signatures provide part of the solution, but the main benefits are lost if a trusted third party is still required to prevent double-spending.",
		"1eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hXrER9RhYy3Imek+ouGzV6t+hFd+7Xod7ZF8HCzdFy6d8B+4xRfGKBepOJhDQ/Jmei5JHWx8KWX0yMWcuf6i9rrzXzKbQIrPJZ7NrbQUJdsE7atUmqV4gd5i1b/mbzGnL8ak3/qgjvwPN2ksqwMnCiGO3Lt9kFDuDDYSwqi0zwwxxuunc7bqf8HTF4bVPi/Rdyo8p6+V9EWzZ4AKgflZwfoAH63TcTqzAP1gjf7To8q02xIc8fTM3GkWVOgquuYSYkt2X18QRlpNQ0JZf7ynUY5sFw7pLoVmxgMedFGSN01hBhIEPNOJl/+9JFbfLDLe1NLuGa0QuX5pM2K8ndzR1LliVbth7bNFSDcAVKWbQSC57jSoip3+gDgy4ElnDxwi58cOlVncM+OVVoM60T3KfyAONZmVv2BwE3k6u3Wzy2JRh23o6JFhOGZH61WLZZtpq5vz/be2w8IaUByuvyqbMQmNk=",
	)
}
