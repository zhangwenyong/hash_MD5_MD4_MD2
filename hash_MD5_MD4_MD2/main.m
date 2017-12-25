//
//  main.m
//  hash_MD5_MD4_MD2
//
//  Created by 张文勇 on 2017/12/22.
//  Copyright © 2017年 张文勇. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>

#import <CommonCrypto/CommonHMAC.h>


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
   
    NSLog(@"-MD_2----%@-----",resultStr);
    
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
    
    NSLog(@"====MD_2fen==%@======",resultStr);
    
}

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


#pragma mark ====Base64 原理。
static const char base64EncodingTable[64]
= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
NSString *ZWY_base64(NSData *data)
{
    
    NSUInteger length = data.length;
    
    if (length == 0)
        return @"";
    //这个是计算长度的。算法  算 输出的字节的长度。算输出字节的长度。 就是加 上一个2 才最大可能保证空间的正确性
    NSUInteger out_length = ((length + 2) / 3) * 4;
    //申请空间 申请空间 申请空间 生情孔家 申请空间
    
    //申请空间的正确性 保证 申请空间的正确性。保证生情空间的正确性。保证 申请空间的正确性。 保证申请空间的正确性
    uint8_t *output = malloc(((out_length + 2) / 3) * 4);
    if (output == NULL)
        return nil;
    //输出 的 话。 输出的话。输出的话
    const char *input = data.bytes;
    NSInteger i, value;
    
    
    for (i = 0; i < length; i += 3) {
        value = 0;
        
        /*
         假设 length =4；
         
         i =0;
         
         j=0; j<3;  j=0, j=1,j=2;
         j=3 j<6   j=3,j=4,j=5;
         
         */
        for (NSInteger j = i; j < i + 3; j++) {
            
            /**
             
             这个循环是吧3个字节的数据加载到value里面  这个循环是把三个字节的数据加载到value里面。这个循环是把三个字节的数据加载到value里面
             
             这个循环是把3个字节的数据加载到value里面 这个循环是把三个字节的数据加载到value里面
             */
            
            
            
            
            
            
            // value 按 2 进制向左移动 8为。
            /**
             下面的式子的表示的是左右<< 代表是的左移的意思  下面式子的意思就是 左移8位 再 赋值给value << 一般是左移的意思。左移之后 在后边补齐0
             */
            value <<= 8;
            
            
            
            
            if (j < length) {
                
                
                /**
                 最开始value是 int类型的。 而且等于0。二进制 是 00000000 00000000 00000000 00000000。共32位
                 */
                
                // 先进行与运算 再进行或运算
                
                /**
                 0XFF  二进制 是  11111111
                 
                 0XFF和input[j]进行与运算 是 把 input[j] 高位的置0  变成 形如 0000000 00000000 00000000 10101101；
                
                  然后再和上一次左移 8位value 进行或预算 加入原来的value 是 0000000 0000000 00000000 10111111；
                 左移之后 就会变成 00000000 00000000 10111111 0000000
                 
                 和input[j] 或运算之后 就把 这个字节的数据加入到value 里面了
                 
                 3次循环之后。就会把。3个字节的数据加入value里面   为后来的把3个字节分生4个字节做准备
                 */
                
                value |= (0xFF & input[j]);
            
                
             
            }
        }
        
        
        
        /**
         
         */
        NSInteger index = (i / 3) * 4;
        
        
        /**
         0X3F 换算成2进制 是 00111111 再和 右移18位 还剩6位的value 重新组合成一个字节的数据  保留6位 。 其余的置0。
         */
        output[index + 0] = base64EncodingTable[(value >> 18) & 0x3F];
        
        /*
         0X3F 第二个字母。第二个字母的
         */
        output[index + 1] = base64EncodingTable[(value >> 12) & 0x3F];
        /*
         
         第三个字母。如果 是补上的 字节 就 直接是 =号
         
         */
        
        output[index + 2] = ((i + 1) < length)
        ? base64EncodingTable[(value >> 6) & 0x3F]
        : '=';
        
        /*
         第四个字母。 如果是 补上的字节 就直接 是 =号。如果是 补上的字节 就直接是 =号。
         如果是补上的字节 就直接是 =号。 如果是补上的字节 就直接是 =号了
         
         */
        output[index + 3] = ((i + 2) < length)
        ? base64EncodingTable[(value >> 0) & 0x3F]
        : '=';
    }
    
    NSString *base64 = [[NSString alloc] initWithBytes:output
                                                length:out_length
                                              encoding:NSASCIIStringEncoding];
    free(output);
    
    return base64;
}


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *md2 = @"dwedwaedaew";
        
        NSData *data = [md2 dataUsingEncoding:NSUTF8StringEncoding];
        
        MD_2(data);
        
        MD_2fen(data);
        
        HMac_MD5(data, @"123");
        HMac_MD5_2(data, @"123");
        
        
        NSString *base62zi = ZWY_base64(data);
        
        
        NSLog(@"===----%@---=====",base62zi);
        
        
        
        
        
    }
    return 0;
}
