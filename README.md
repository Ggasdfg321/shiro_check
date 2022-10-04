# shiro_check
批量对存在Shiro框架的目标爆破Key
## 优点
* 速度快
* 准确率高（几乎无误报）
## 使用教程
文件说明
>*target.txt 存放目标的文件（可修改）*

>*key.txt 存放Key的文件（可修改）*

命令说明
>-f   `批量目标路径 (default "target.txt")`

>-fk  `key文件路径 (default "key.txt")`

>-m `发送请求的模式GET/POST (default "get")`

>-p`设置POST请求参数,例如：username=admin&password=123456，只有POST请求的时候这个参数才有效`

>-proxy `代理设置，支持http/socks5/socks4`

>-rm `密钥关键字 (default "rememberMe")`

>-t `同一时间内爆破多少个目标 (default 10)`

>-tk `同一个时间内爆破目标多少个Key (default 10)，建议设置为10，防止把网站给跑崩溃`

>-o `保存爆破结果目录，为空表示不保存结果 (default "output")`

>-x `如果需要添加其他状态码则逗号分隔（502,500）,爆破Key的时候过滤状态码防止爆破速度过快导致误报 (default "502")`
![image](https://user-images.githubusercontent.com/65237278/193859620-cc52f624-80d0-43c6-957b-8d6de42153a7.png)

如何使用呢？

把目标丢在target.txt文件，然后如果没有什么特殊配置，直接运行./shiro_check.exe或者./shiro_check即可
![image](https://user-images.githubusercontent.com/65237278/193859421-ff55af06-01cf-4272-bfdf-fb896cb944cc.png)

## 编译（如果需要编译32位的或者是其他操作系统请自行编译）
>go mod tidy

>go env -w xxx=xxx （xxx根据自己的需求进行修改）

>go build -o ./

## 注意事项
请勿对没有授权的网站进行测试
