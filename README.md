# hash_MD5_MD4_MD2

# 摘要详解
摘要主要是防止 数据被私自改动的方法 其中用到的函数就是摘要函数 这些函数的输入是任意大小的信息 但是输出是固定大小的摘要 。
摘要有个重要的特性 如果改变了输入的信息的任何内容。即使是非常微小的变化 输出都会发生不可与之的变化 也就是说输入信息的任何改动都会影响最后的输出。总之 摘要算法 就是从一个给定的文本中产生数字签名 。数字签名可以防止 有人从数字签名中 获取文本信息或者 改动文本信息。摘要算法的数字签名原理可以在狠多加密算法中使用 如S/kEY和PGP。
现在很流行的摘要算法 有MD4和MD5 客户机和服务器必须使用相同的算法 MD4 麻省理工学院1990设计的一种信息摘要算法 他是用来 测试信息完整性密码散列函数的实行  其摘要长度为128位
一般128位的MD4散列标示为32为的16进制数字这个算法影响了后来的很多算法
hash 一般翻译为散列 但是也可音译 哈希就是把任意长度的输入 通过散列算法，变成固定长度输出 ，该输出就是散列值。
这种转换是一种压缩映射 也就是 一般来讲散列值的空间大小小输入的空间。不同的输入可能产生相同的散列 。但是不能从散列 来确定唯一的值
数学表述为
```
h = H(M) 其中H()是单向散列函数，M是任意长度明文 h是固定长度 散列值
```

在信算法 还需息安全领域应用的hash要满足其他关键特性 :
* 第一个就是单向性  从预映射可以简单快速得到散列值 而在计算上不可能构造一个预映射 把散列结果等与一个特定的散列值
即构造一个相应 M = H（h）不可行 这样散列值就能在统计上唯一的表征输入值 。因此密码学上的Hash又被成为消息摘要，就是要求能方便的 将消息进行摘要 但是在摘要中不能得到比摘要多的关于消息的信息
* 第二 是抗冲突性 即在统计上无法产生两个相同的散列值的预映射 。给定M，计算上无法找到M'，满足H(M)=H(M')这就是弱冲突性  计算上也难以找到任意以对M和M‘使满足H(M) = H(M')次为抗强冲突性 要求强抗冲突性主要是为了当值所谓的生日攻击。在一个10人的团体中，你能找到和你生日相同的人的概率是2.4%，而在同一团体中，有2人生日相同的概率是11.7%。类似的，当预映射的空间很大的情况下，算法必须有足够的强度来保证不能轻易找到"相同生日"的人。
* 第三就是映射分布均匀性和差分分布均匀性散列结果中为0的bit和为1的bit 其总是应该大郅相等 输入中一个bit的变化散列中应该有一半以上的bit的变化这叫雪崩效应 。要使输入中一个bit的变化 散列中应该有一半以上的bit发生变化 其实质就是 要使输入的每一个bit的信息尽量均匀的反映到输出的每一个bit上去输出的每一个bit的变化都是尽可能的多的出入bit的一起作用的结果。
Damgard 和 Merkle 定义了所谓“压缩函数(compression function)”，就是将一个固定长度输入，变换成较短的固定长度的输出，这对密码学实践上 Hash 函数的设计产生了很大的影响。


hash函数就是设计为基于特定压缩函数的不断重复“压缩”输入的分组和前一次压缩处理的结果的过程直到整个消息都被压缩完毕，最后的输出作为整个消息的散列值。尽管还缺乏严格的证明，但绝大多数业界的研究者都同意，如果压缩函数是安全的，那么以上述形式散列任意长度的消息也将是安全的。这就是所谓 Damgard/Merkle 结构：任意长度的消息被分拆成符合压缩函数的要求的分组，最后一个分组可能需要在末尾添加特定的填充字节，这些分组将被顺序处理,除了第一个消息分组将与散列初始化值一起作为压缩函数的输入外，当前分组将和前一个分组的压缩函数输出一起被作为这一次压缩的输入，而其输出又将被作为下一个分组压缩函数输入的一部分，直到最后一个压缩函数的输出，将被作为整个消息散列的结果。

MD5和SHA1可以说是目前最广泛的Hash算法 而他们又是都是以MD4为基础设计的

1、MD4

MD4(RFC 1320)是 MIT 的 Ronald L. Rivest 在 1990 年设计的，MD 是 Message Digest 的缩写。它适用在32位字长的处理器上用高速软件实现--它是基于 32 位操作数的位操作来实现的。它的安全性不像RSA那样基于数学假设，尽管 Den Boer、Bosselaers 和 Dobbertin 很快就用分析和差分成功的攻击了它3轮变换中的 2 轮，证明了它并不像期望的那样安全，但它的整个算法并没有真正被破解过，Rivest 也很快进行了改进。

下面是一些MD4散列结果的例子：
MD4 ("") = 31d6cfe0d16ae931b73c59d7e0c089c0
MD4 ("a") = bde52cb31de33e46245e05fbdbd6fb24
MD4 ("abc") = a448017aaf21d8525fc10ae87aa6729d
MD4 ("message digest") = d9130a8164549fe818874806e1c7014b
MD4 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = e33b4ddc9c38f2199c3e7b164fcc0536


2、MD5

MD5(RFC 1321)是 Rivest 于1991年对MD4的改进版本。它对输入仍以512位分组，其输出是4个32位字的级联，与 MD4 相同。它较MD4所做的改进是：

1） 加入了第四轮
2） 每一步都有唯一的加法常数；
3） 第二轮中的G函数从((X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)) 变为 ((X ∧ Z) ∨ (Y ∧ ～Z))以减小其对称性；
4） 每一步都加入了前一步的结果，以加快"雪崩效应"；
5)  改变了第2轮和第3轮中访问输入子分组的顺序，减小了形式的相似程度；
6)  近似优化了每轮的循环左移位移量，以期加快"雪崩效应"，各轮的循环左移都不同。

尽管MD5比MD4来得复杂，并且速度较之要慢一点，但更安全，在抗分析和抗差分方面表现更好。

消息首先被拆成若干个512位的分组，其中最后512位一个分组是“消息尾+填充字节(100…0)+64位消息长度”，以确保对于不同长度的消息，该分组不相同。而4个32位寄存器字初始化为A=0x01234567，B=0x89abcdef，C=0xfedcba98，D=0x76543210，它们将始终参与运算并形成最终的散列结果。

接着各个512位消息分组以16个32位字的形式进入算法的主循环，512位消息分组的个数据决定了循环的次数。主循环有4轮，每轮分别用到了非线性函数
F(X, Y, Z) = (X ∧ Y) ∨ (～X ∧ Z)
G(X, Y, Z) = (X ∧ Z) ∨ (Y ∧ ～Z)
H(X, Y, Z) =X ⊕ Y ⊕ Z
I(X, Y, Z) = X ⊕ (Y ∨ ～Z)

这4轮变换是对进入主循环的512位消息分组的16个32位字分别进行如下操作：将A、B、C、D的副本a、b、c、d中的3个经F、G、H、I运算后的结果与第4个相加，再加上32位字和一个32位字的加法常数，并将所得之值循环左移若干位，最后将所得结果加上a、b、c、d之一，并回送至ABCD，由此完成一次循环。

所用的加法常数由这样一张表T[i]来定义，其中i为1…64，T[i]是i的正弦绝对值之4294967296次方的整数部分，这样做是为了通过正弦函数和幂函数来进一步消除变换中的线性。

当所有512位分组都运算完毕后，ABCD的级联将被输出为MD5散列的结果。下面是一些MD5散列结果的例子：
MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
MD5 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = 57edf4a22be3c955ac49da2e2107b67a
参考相应RFC文档可以得到MD4、MD5算法的详细描述和算法的C源代码。
3、SHA1 及其他

SHA1是由NIST NSA设计为同DSA一起使用的，访问http://www.itl.nist.gov/fipspubs可以得到它的详细规范--[/url]"FIPS PUB 180-1 SECURE HASH STANDARD"。它对长度小于264的输入，产生长度为160bit的散列值，因此抗穷举(brute-force)性更好。SHA-1 设计时基于和MD4相同原理,并且模仿了该算法。因为它将产生160bit的散列值，因此它有5个参与运算的32位寄存器字，消息分组和填充方式与MD5相同，主循环也同样是4轮，但每轮进行20次操作，非线性运算、移位和加法运算也与MD5类似，但非线性函数、加法常数和循环左移操作的设计有一些区别，可以参考上面提到的规范来了解这些细节。下面是一些SHA1散列结果的例子：

SHA1 ("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
SHA1 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1

其他一些知名的Hash算法还有MD2、N-Hash、RIPE-MD、HAVAL等等。上面提到的这些都属于"纯"Hash算法。还有另2类Hash算法，一类就是基于对称分组算法的单向散列算法，典型的例子是基于DES的所谓Davies-Meyer算法，另外还有经IDEA改进的Davies-Meyer算法，它们两者目前都被认为是安全的算法。另一类是基于模运算/离散对数的，也就是基于公开密钥算法的，但因为其运算开销太大，而缺乏很好的应用前景。


Hash算法在信息安全方面的应用主要体现在以下的3个方面：

1) 文件校验

我们比较熟悉的校验算法有奇偶校验和CRC校验，这两种校验并没有抗数据篡改的能力，它们一定程度上能检测并纠正数据传输中的信道误码，但却不能防止对数据的恶意破坏。
MD5 Hash算法的"数字指纹"特性，使它成为目前应用最广泛的一种文件完整性校验和(Checksum)算法，不少Unix系统有提供计算md5 checksum的命令。它常被用在下面的2种情况下：
第一是文件传送后的校验，将得到的目标文件计算 md5 checksum，与源文件的md5 checksum 比对，由两者 md5 checksum 的一致性，可以从统计上保证2个文件的每一个码元也是完全相同的。这可以检验文件传输过程中是否出现错误，更重要的是可以保证文件在传输过程中未被恶意篡改。一个很典型的应用是ftp服务，用户可以用来保证多次断点续传，特别是从镜像站点下载的文件的正确性。
更出色的解决方法是所谓的代码签名，文件的提供者在提供文件的同时，提供对文件Hash值用自己的代码签名密钥进行数字签名的值，及自己的代码签名证书。文件的接受者不仅能验证文件的完整性，还可以依据自己对证书签发者和证书拥有者的信任程度，决定是否接受该文件。浏览器在下载运行插件和java小程序时，使用的就是这样的模式。

第二是用作保存二进制文件系统的数字指纹，以便检测文件系统是否未经允许的被修改。不少系统管理/系统安全软件都提供这一文件系统完整性评估的功能，在系统初始安装完毕后，建立对文件系统的基础校验和数据库，因为散列校验和的长度很小，它们可以方便的被存放在容量很小的存储介质上。此后，可以定期或根据需要，再次计算文件系统的校验和，一旦发现与原来保存的值有不匹配，说明该文件已经被非法修改，或者是被病毒感染，或者被木马程序替代。TripWire就提供了一个此类应用的典型例子。

2) 数字签名

Hash 算法也是现代密码体系中的一个重要组成部分。由于非对称算法的运算速度较慢，所以在数字签名协议中，单向散列函数扮演了一个重要的角色。

在这种签名协议中，双方必须事先协商好双方都支持的Hash函数和签名算法。
签名方先对该数据文件进行计算其散列值，然后再对很短的散列值结果--如Md5是16个字节，SHA1是20字节，用非对称算法进行数字签名操作。对方在验证签名时，也是先对该数据文件进行计算其散列值，然后再用非对称算法验证数字签名。

3) 鉴权协议

如下的鉴权协议又被称作"挑战--认证模式：在传输信道是可被侦听，但不可被篡改的情况下，这是一种简单而安全的方法。

需要鉴权的一方，向将被鉴权的一方发送随机串（“挑战”），被鉴权方将该随机串和自己的鉴权口令字一起进行 Hash 运算后，返还鉴权方，鉴权方将收到的Hash值与在己端用该随机串和对方的鉴权口令字进行 Hash 运算的结果相比较（“认证”），如相同，则可在统计上认为对方拥有该口令字，即通过鉴权。

散列算法长期以来一直在计算机科学中大量应用，随着现代密码学的发展，单向散列函数已经成为信息安全领域中一个重要的结构模块，我们有理由深入研究其设计理论和应用方法。
下面让我们看看具体的代码怎么些 看看咋样  具体的代码咋写

```
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>



/**
CommonDigest.h 这个文件里的加密方法 都是按着一种方式使用的都一样。都是按着一种方式使用的都一样 都是按着一种方式使用的 都一样 都是按着一种范式使用的饿 都一样 都一样都一样。都一样 都一样 都一样
*/

void MD_2(NSData *data)
{
//
//摘要长度 如果一字节为单位 就是16个字节 128位
// 定义一个数组来储存 加密号的32位16进制数 一个16进制数是4位 正好是128位
// CC_MD2_DIGEST_LENGTH   DIGEST 摘要。 摘要长度。这是MD2 的摘要长度
//声明一个无符号 字符数组 来储存 生成的摘要
unsigned char resulet[CC_MD2_DIGEST_LENGTH];
//摘取摘要
CC_MD2(data.bytes, (CC_LONG)data.length, resulet);
//合成字符串
// x是以16进制输出字符串
// 02。是不满两位补齐 0
NSString *resultStr = [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",resulet[0],resulet[1],resulet[2],resulet[3],resulet[4],resulet[5],resulet[6],resulet[7],resulet[8],resulet[9],resulet[10],resulet[11],resulet[12],resulet[13],resulet[14],resulet[15]];

NSLog(@"-----%@-----",resultStr);

}


void MD_2fen(NSData *data)
{


///这个方法和上面的饿方法是一模一样的就是分布转换 就是分布转换 就是分布转换 就是分布转换。就是分布转换 就是分布转换

CC_MD2_CTX Z_MD2;

CC_MD2_Init(&Z_MD2);

CC_MD2_Update(&Z_MD2, data.bytes, (CC_LONG)data.length);

unsigned char resulet[CC_MD2_DIGEST_LENGTH];
CC_MD2_Final(resulet, &Z_MD2);

NSString *resultStr = [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",resulet[0],resulet[1],resulet[2],resulet[3],resulet[4],resulet[5],resulet[6],resulet[7],resulet[8],resulet[9],resulet[10],resulet[11],resulet[12],resulet[13],resulet[14],resulet[15]];

NSLog(@"======%@======",resultStr);

}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSString *md2 = @"dwedwaedaew";

NSData *data = [md2 dataUsingEncoding:NSUTF8StringEncoding];

MD_2(data);

MD_2fen(data);
}
return 0;
}
```


### HMac

HMac是密钥相关的哈希算法 。和之前的算法不同之处在于一个密钥，才能生成输出 。 主要是基于签名散列算法。可以认为散列算法 加入了加密逻辑 所以相比 SHA 算法更难破解 包含下面的算法

```
/*!
@enum       CCHmacAlgorithm
@abstract   Algorithms implemented in this module.

@constant   kCCHmacAlgSHA1      HMAC with SHA1 digest
@constant   kCCHmacAlgMD5       HMAC with MD5 digest
@constant   kCCHmacAlgSHA256    HMAC with SHA256 digest
@constant   kCCHmacAlgSHA384    HMAC with SHA384 digest
@constant   kCCHmacAlgSHA512    HMAC with SHA512 digest
@constant   kCCHmacAlgSHA224    HMAC with SHA224 digest
*/
enum {
kCCHmacAlgSHA1,
kCCHmacAlgMD5,
kCCHmacAlgSHA256,
kCCHmacAlgSHA384,
kCCHmacAlgSHA512,
kCCHmacAlgSHA224
};
```
HMac的应用场景是
* 1 密钥的散列存储 因为需要散列的时候 需要密码实际相当于算法里面加了盐  使用的密码 要随机 和用户相关
* 2 用于数据签名 双方使用相同的密钥 。然后做签名验证 密钥可以固化 也可以 再在回话前协商。


总结


* 1密码保存和传输需要做散列处理。但是散列算法主要是脱敏，不能替代加密算法。
* 2 如今常用的Md5算法和SHA1算法都不再安全。所以推荐使用SHA-2相关算法。
* 3散列算法应该加入盐值即：result=HASH(password+salt)。其中盐值应该是随机字符串且每个用户不一样。
* 4 HMac引入了秘钥的概念，如果不知道秘钥，秘钥不同，散列值也不同，相当于散列算法加入了盐值。可以把它当做更安全的散列算法使用。

```
// HMac 是密钥相关的哈希算法。
/**
相关的方法在CommonHMac.h 这个头文件里面

*/
void HMac_MD5(NSData *data,NSString *key)
{

unsigned char resulet[CC_MD5_DIGEST_LENGTH];



CCHmac(kCCHmacAlgMD5, key.UTF8String, (size_t)key.length, data.bytes, (size_t)data.length, resulet);


NSString *resultStr = [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",resulet[0],resulet[1],resulet[2],resulet[3],resulet[4],resulet[5],resulet[6],resulet[7],resulet[8],resulet[9],resulet[10],resulet[11],resulet[12],resulet[13],resulet[14],resulet[15]];

NSLog(@"===HMac_MD5===%@======",resultStr);

}

//第二种Hmac 的方法
void HMac_MD5_2(NSData *data,NSString *key)
{



unsigned char resulet[CC_MD5_DIGEST_LENGTH];



CCHmacContext contex;

CCHmacInit(&contex, kCCHmacAlgMD5, key.UTF8String, (size_t)key.length);

CCHmacUpdate(&contex, data.bytes, (size_t)data.length);

CCHmacFinal(&contex, resulet);


NSString *resultStr = [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",resulet[0],resulet[1],resulet[2],resulet[3],resulet[4],resulet[5],resulet[6],resulet[7],resulet[8],resulet[9],resulet[10],resulet[11],resulet[12],resulet[13],resulet[14],resulet[15]];

NSLog(@"===HMac_MD5_2===%@======",resultStr);


}

```




