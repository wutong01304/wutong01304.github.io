---
title: RSA基本原理+常见攻击方法
date: 2023-07-21 10:46:36
tags: [Crypto,RSA]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSAcover.jpg"
categories: [Study]
---

RSA是一种非对称加密算法，使用两个密钥，一个用来加密消息和验证数字签名，称为公钥，另一个用来解密，称为私钥。公钥通常是公开的，用于加密会话密钥、验证数字签名或加密可以用相应的私钥解密的数据。私钥则是非公开的，用于解密由公钥加密的数据。本文介绍一些RSA的攻击方法。


------

# 一、基本原理

## 1.1 RSA算法

1. 任意选取两个不同的大素数p和q计算乘积

   ![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/1.png)

2. 任意选取一个大整数e，满足

   ![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/2.png)

   整数e用做加密钥（注意：e的选取是很容易的，例如，所有大于p和q的素数都可用

3. 确定的解密钥d，满足

   ![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/3.png)

   即de是一个任意的整数

   ![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/4.png)

   所以，若知道 e 和 φ(n )，则很容易计算出d ；

4. 公开整数n和e，秘密保存d ；

5. 将明文m（m<n是一个整数）加密成密文c，加密算法为

   ![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/5.png)

   

6. 将密文c解密为明文m，解密算法为

   ![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/6.png)


这样我们可以得到 公钥对（n,e）、 私钥对（n,d）

## 1.2 证明

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/7.png)

已知

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/8.png)

由欧拉定理可知

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/9.png)

​	补：e与φ(n)不互素时，

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/10.png)

可以转化为

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/11.png)

此时就满足互素的条件，因此求解时，需要对m开根号

------

# 二、 已知 dp、dq、p、q、c 求m

## 2.1 原理

已知：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/12.png)

推论：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/13.png)

证明：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/14.png)

 同时取余p,q，即证明成立

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/15.png)

合并得：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/16.png)

即：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/17.png)

费马小定理推出：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/18.png)

## 2.2 例子

buuctf上例子，由于不需要链接靶机，这里就不给题目，直接给xp了。

```python
import gmpy2
p=8637633767257008567099653486541091171320491509433615447539162437911244175885667806398411790524083553445158113502227745206205327690939504032994699902053229
q=12640674973996472769176047937170883420927050821480010581593137135372473880595613737337630629752577346147039284030082593490776630572584959954205336880228469
dp=6500795702216834621109042351193261530650043841056252930930949663358625016881832840728066026150264693076109354874099841380454881716097778307268116910582929
dq=783472263673553449019532580386470672380574033551303889137911760438881683674556098098256795673512201963002175438762767516968043599582527539160811120550041
c=24722305403887382073567316467649080662631552905960229399079107995602154418176056335800638887527614164073530437657085079676157350205351945222989351316076486573599576041978339872265925062764318536089007310270278526159678937431903862892400747915525118983959970607934142974736675784325993445942031372107342103852
phi = gmpy2.invert(p,q)#求逆元p-1
m1 = pow(c,dp,p) #c^dp mod p
m2 = pow(c,dq,q)
m = (((m2-m1)*phi)%q)*p+m1
print(m)                               #10进制明文
print(hex(m)[2:])                      #16进制明文
print(bytes.fromhex(hex(m)[2:]))       #16进制转文本


```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/r1.png?x-oss-process=style/watermark)

------

# 三、 已知c1、c2、e1、e2、n求m

## 3.1 原理

共模数攻击。通过扩展欧几里得算法，可以找到整数a、b使得

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/19.png)

证明：

已知

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/20.png)

得

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/21.png)

又因为

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/22.png)

且

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/23.png)

即

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/24.png)

可得

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/25.png)

如果b为负数，将它转为正值并求c2的逆元 c^-1，即

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/26.png)

## 3.2 例子

```python
import libnum
import gmpy2
def egcd(a, b):#求a*e1+b*e2中的a,b
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y #g=1 y=a x=b

def main():  

	n=
22708078815885011462462049064339185898712439277226831073457888403129378547350292420267016551819052430779004755846649044001024141485283286483130702616057274698473611149508798869706347501931583117632710700787228016480127677393649929530416598686027354216422565934459015161927613607902831542857977859612596282353679327773303727004407262197231586324599181983572622404590354084541788062262164510140605868122410388090174420147752408554129789760902300898046273909007852818474030770699647647363015102118956737673941354217692696044969695308506436573142565573487583507037356944848039864382339216266670673567488871508925311154801
    c1=
22322035275663237041646893770451933509324701913484303338076210603542612758956262869640822486470121149424485571361007421293675516338822195280313794991136048140918842471219840263536338886250492682739436410013436651161720725855484866690084788721349555662019879081501113222996123305533009325964377798892703161521852805956811219563883312896330156298621674684353919547558127920925706842808914762199011054955816534977675267395009575347820387073483928425066536361482774892370969520740304287456555508933372782327506569010772537497541764311429052216291198932092617792645253901478910801592878203564861118912045464959832566051361
    c2=
18702010045187015556548691642394982835669262147230212731309938675226458555210425972429418449273410535387985931036711854265623905066805665751803269106880746769003478900791099590239513925449748814075904017471585572848473556490565450062664706449128415834787961947266259789785962922238701134079720414228414066193071495304612341052987455615930023536823801499269773357186087452747500840640419365011554421183037505653461286732740983702740822671148045619497667184586123657285604061875653909567822328914065337797733444640351518775487649819978262363617265797982843179630888729407238496650987720428708217115257989007867331698397
    
    e1 = 11187289
    e2 = 9647291
    s = egcd(e1, e2)
    s1 = s[1]
    s2 = s[2]
    #如果求得a,b为负数，就把他们转为正数,并求相应c的逆元
    if s1 < 0:
        s1 = - s1
        c1 = gmpy2.invert(c1, n)
    elif s2 < 0:
        s2 = - s2
        c2 = gmpy2.invert(c2, n)

    m = pow(c1, s1, n) * pow(c2, s2, n) % n
    print(m)
    print(libnum.n2s(int(m)).decode("utf-8"))#数字转字符串


if __name__ == '__main__':
    #print(egcd(23,37))
    main()


```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/r2.png?x-oss-process=style/watermark)

------

# 四 已知c、dp、n、e求m

## 4.1 原理

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/27.png)

两边乘e

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/28.png)

得

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/29.png)

观察等式，左边e∙dp是已知的，右边(p-1)比dp要大，则(r-k)必然比e小，我们从1到e枚举(r-k)=x，然后看e∙dp-1能否被x整除。如果能，则我们可以得到

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/30.png)

接下来就可以把p,q都求出来，从而解密  其实可以直接暴力分解n得p,q（如果n可以分解的话）

## 4.2 例子

```python
import gmpy2
import libnum
e = 65537
n=248254007851526241177721526698901802985832766176221609612258877371620580060433101538328030305219918697643619814200930679612109885533801335348445023751670478437073055544724280684733298051599167660303645183146161497485358633681492129668802402065797789905550489547645118787266601929429724133167768465309665906113

dp=905074498052346904643025132879518330691925174573054004621877253318682675055421970943552016695528560364834446303196939207056642927148093290374440210503657
 
c=140423670976252696807533673586209400575664282100684119784203527124521188996403826597436883766041879067494280957410201958935737360380801845453829293997433414188838725751796261702622028587211560353362847191060306578510511380965162133472698713063592621028959167072781482562673683090590521214218071160287665180751\
 
for x in range(1, e):
    if(e*dp%x==1):
        p=(e*dp-1)//x+1
        if(n%p!=0):
            continue
        q=n//p
        phi=(p-1)*(q-1)
        d=gmpy2.invert(e, phi)
        m=pow(c, d, n)
        print(hex(m))
        print(libnum.n2s(int(m)))

```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/r3.png?x-oss-process=style/watermark)

------

# 五、 已知n、c、e 求m。（n很大，e很小）

## 5.1 原理

1、由于 

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/31.png)

  e很小，n很大，  有可能小于n，此时 c=m^e

2、当

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/32.png)

  时，可以对k进行爆破

## 5.2 例子

```python
from gmpy2 import iroot
import libnum
e = 0x3
c = 2776571135646565181849912433877522437622755332262910824866791711
n=85793694792655420934945863688968944466300304898903354212780512650924132933351787673979641944071634528676901506049360194331553838080226562532784448832916022442020751986591703547743056267118831445759258041047213294368605599719242059474324548598203039032847591828382166845797857139844445858881218318006747115157

k = 0
while 1:
    res = iroot(c+k*n,e)  #c+k*n 开3次方根 能开3次方即可
    #print(res)
    #res = (mpz(13040004482819713819817340524563023159919305047824600478799740488797710355579494486728991357), True)
    if(res[1] == True):
        print(k)
        print(res[0])
        print(libnum.n2s(int(res[0])).decode("utf-8")) #转为字符串
        break
    k=k+1
```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/r4.png?x-oss-process=style/watermark)

------

# 六、 低加密指数广播攻击（模数n、密文c不同，明文m、加密指数e相同）

## 6.1 原理

如果选取的加密指数较低，并且使用了相同的加密指数给一个接受者的群发送相同的信息，那么可以进行广播攻击得到明文。
适用范围：模数n、密文c不同，明文m、加密指数e相同。
一般的话e=k。 k是题目给出的n和c的组数。

例如下面得就是e=k=3

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/33.png)

使用不同模数n，相同的公钥指数e加密相同的信息。就会得到多个

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/34.png)

将m^e视为一个整体M，求得m^e的值，直接开e方即可。

构造同余方程组：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/35.png)

有唯一解，解为

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/36.png)

其中

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/37.png)



证明如下：

Ni的因数中包含除了ni其他所有模数，因此对其他所有模数取模都为0

例如

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/38.png)

所以

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/39.png)

由于

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/40.png)

分析一下这样构造的解M中每一项的系数，对所有的i，

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/41.png)

## 6.2、例子

```python
import gmpy2
import  binascii

#利用中国剩余定理求解同余方程，aList：余数，mList：模数
def CRT(cList, nList):
    M = 1
    for i in nList:
        M = M * i   #计算M = n1*n2*n3
    #print(M)
    x = 0
    for i in range(len(nList)):
        Mi = M // nList[i]   #计算Mi
        Mi_inverse = gmpy2.invert(Mi, nList[i]) #计算Mi的逆元
        x += cList[i] * Mi * Mi_inverse #构造x各项
    x = x % M
    return x

if __name__ == "__main__":
    #========== n c ==========
    n1 = "331310324212000030020214312244232222400142410423413104441140203003243002104333214202031202212403400220031202142322434104143104244241214204444443323000244130122022422310201104411044030113302323014101331214303223312402430402404413033243132101010422240133122211400434023222214231402403403200012221023341333340042343122302113410210110221233241303024431330001303404020104442443120130000334110042432010203401440404010003442001223042211442001413004"
    c1 = "310020004234033304244200421414413320341301002123030311202340222410301423440312412440240244110200112141140201224032402232131204213012303204422003300004011434102141321223311243242010014140422411342304322201241112402132203101131221223004022003120002110230023341143201404311340311134230140231412201333333142402423134333211302102413111111424430032440123340034044314223400401224111323000242234420441240411021023100222003123214343030122032301042243"
    n2 = "302240000040421410144422133334143140011011044322223144412002220243001141141114123223331331304421113021231204322233120121444434210041232214144413244434424302311222143224402302432102242132244032010020113224011121043232143221203424243134044314022212024343100042342002432331144300214212414033414120004344211330224020301223033334324244031204240122301242232011303211220044222411134403012132420311110302442344021122101224411230002203344140143044114"
    c2 = "112200203404013430330214124004404423210041321043000303233141423344144222343401042200334033203124030011440014210112103234440312134032123400444344144233020130110134042102220302002413321102022414130443041144240310121020100310104334204234412411424420321211112232031121330310333414423433343322024400121200333330432223421433344122023012440013041401423202210124024431040013414313121123433424113113414422043330422002314144111134142044333404112240344"
    n3 = "332200324410041111434222123043121331442103233332422341041340412034230003314420311333101344231212130200312041044324431141033004333110021013020140020011222012300020041342040004002220210223122111314112124333211132230332124022423141214031303144444134403024420111423244424030030003340213032121303213343020401304243330001314023030121034113334404440421242240113103203013341231330004332040302440011324004130324034323430143102401440130242321424020323"
    c3 = "10013444120141130322433204124002242224332334011124210012440241402342100410331131441303242011002101323040403311120421304422222200324402244243322422444414043342130111111330022213203030324422101133032212042042243101434342203204121042113212104212423330331134311311114143200011240002111312122234340003403312040401043021433112031334324322123304112340014030132021432101130211241134422413442312013042141212003102211300321404043012124332013240431242"
    
    cList = [int(c1,5), int(c2,5), int(c3,5)]
    nList = [int(n1,5), int(n2,5), int(n3,5)]
    m_e = CRT(cList, nList) #计算m^e
    #print(m_e)
    for e in range(1, 10):  #遍历e求解
        m, f = gmpy2.iroot(m_e, e) #m_e开e次根
        print("加密指数e = %d："%e)
        m = hex(m)[2:]
        if len(m)%2 == 1:
            m = m + '0' #binascii.unhexlify()参数长度必须为偶数，因此做一下处理
        flag = binascii.unhexlify(m)
        print(flag)
```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/r5.png?x-oss-process=style/watermark)

# 七、低解密指数攻击（已知n、e，求d；e很大，d很小）

## 7.1 原理

参考链接：https://blog.csdn.net/weixin_46395886/article/details/114757828

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/42.png)

所以有下面计算：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/43.png)

由连分数的理论可知，此时 t/a 是b/n 的一个收敛子。因为n和b都是公开的，计算收敛子是容易的。我们只要计算出 b/n 的所有的收敛子，看哪个收敛子能够分解n 。因为如果 t/a 是收敛子，我们就有了a 和t 的值，依据ϕ ( n ) = ( a b − 1 ) 就可以计算出ϕ ( n )，进而可以解一元二次方程求出p，以此为判断依据确定哪个收敛子才是真正的 t 和a 。

## 7.2 例子

代码来源于链接：https://github.com/pablocelayes/rsa-wiener-attack

```python
'''
Created on Dec 14, 2011

@author: pablocelayes
'''

import ContinuedFractions, Arithmetic, RSAvulnerableKeyGenerator

def hack_RSA(e,n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)
    
    for (k,d) in convergents:
        
        #check if d is actually the key
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s*s - 4*n
            if(discr>=0):
                t = Arithmetic.is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
                    print("Hacked!")
                    return d

# TEST functions

def test_hack_RSA():
    print("Testing Wiener Attack")
    times = 5
    
    while(times>0):
        e,n,d = RSAvulnerableKeyGenerator.generateKeys(1024)
        print("(e,n) is (", e, ", ", n, ")")
        print("d = ", d)
    
        hacked_d = hack_RSA(e, n)
    
        if d == hacked_d:
            print("Hack WORKED!")
        else:
            print("Hack FAILED")
        
        print("d = ", d, ", hacked_d = ", hacked_d)
        print("-------------------------")
        times -= 1
def RSA():
    # e = 543692319895782434793586873362429927694979810701836714789970907812484502410531778466160541800747280593649956771388714635910591027174563094783670038038010184716677689452322851994224499684261265932205144517234930255520680863639225944193081925826378155392210125821339725503707170148367775432197885080200905199759978521133059068268880934032358791127722994561887633750878103807550657534488433148655178897962564751738161286704558463757099712005140968975623690058829135
    # n = 836627566032090527121140632018409744681773229395209292887236112065366141357802504651617810307617423900626216577416313395633967979093729729146808472187283672097414226162248255028374822667730942095319401316780150886857701380015637144123656111055773881542557503200322153966380830297951374202391216434278247679934469711771381749572937777892991364186158273504206025260342916835148914378411684678800808038832601224951586507845486535271925600310647409016210737881912119
    e = 51999725233581619348238930320668315462087635295211755849675812266270026439521805156908952855288255992098479180003264827305694330542325533165867427898010879823017054891520626992724274019277478717788189662456052796449734904215067032681345261878977193341769514961038309763898052908572726913209883965288047452751
    n = 68816697240190744603903822351423855593899797203703723038363240057913366227564780805815565183450516726498872118491739132110437976570592602837245705802946829337567674506561850972973663435358068441037127926802688722648016352967768929007662772115485020718202683004813042834036078650571763978066558718285783045969

    d=hack_RSA(e,n)
    print("d=",d)

if __name__ == "__main__":
    #test_is_perfect_square()
    #print("-------------------------")
    RSA()   
```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/RSA/r6.png?x-oss-process=style/watermark)



大数分解工具：

factordb在线分解：http://factordb.com/

win10 yafu-x64：https://sourceforge.net/projects/yafu/