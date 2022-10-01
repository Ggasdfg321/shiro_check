package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

func main() {
	fmt.Println(`
	_____ __    _               ________              __  
   / ___// /_  (_)________     / ____/ /_  ___  _____/ /__
   \__ \/ __ \/ / ___/ __ \   / /   / __ \/ _ \/ ___/ //_/
  ___/ / / / / / /  / /_/ /  / /___/ / / /  __/ /__/ ,<   
 /____/_/ /_/_/_/   \____/   \____/_/ /_/\___/\___/_/|_|  
												
 				version:	1.0
				By:		Ggasdfg321	  
 `)
	KeyFile := flag.String("fk", "key.txt", "key文件路径")
	TargetFile := flag.String("f", "target.txt", "批量目标路径")
	RememberMe := flag.String("rm", "rememberMe", "密钥关键字")
	TargetThread := flag.Int("t", 10, "同一时间内爆破多少个目标")
	KeyThread := flag.Int("tk", 10, "同一个时间内爆破目标多少个Key")
	FilterStatus := flag.String("x", "502", "如果需要添加其他状态码则逗号分隔（502,500）；爆破Key的时候过滤状态码防止爆破速度过快导致误报")
	Proxy := flag.String("proxy", "", "代理设置，支持http/socks5/socks4")
	Method := flag.String("m", "get", "发送请求的模式GET/POST")
	Params := flag.String("p", "", "设置POST请求参数,例如：username=admin&password=123456，只有POST请求的时候这个参数才有效")
	flag.Parse()

	var filters []int
	if !strings.Contains(*FilterStatus, ",") {
		tmp, _ := strconv.Atoi(*FilterStatus)
		filters = []int{tmp}
	}
	string_filters := strings.Split(*FilterStatus, ",")
	for _, filter := range string_filters {
		tmp, _ := strconv.Atoi(filter)
		filters = append(filters, tmp)
	}

	s := Shiro{RememberMe: *RememberMe, TargetThread: *TargetThread, KeyThread: *KeyThread, FilterStatus: filters, Proxy: *Proxy, Method: strings.ToLower(*Method), Params: *Params}

	targetFile, err := ioutil.ReadFile(*TargetFile)
	if err != nil {
		fmt.Println("[-]Target文件不存在或者无权限打开")
		return
	}
	s.targets = strings.Split(string(targetFile), "\r\n")

	Fkeys, err := ioutil.ReadFile(*KeyFile)
	if err != nil {
		fmt.Println("[-]Key文件不存在或者无权限打开")
		return
	}
	keys := strings.Split(string(Fkeys), "\r\n")
	s.Keys = keys

	s.checkTargets()
}
