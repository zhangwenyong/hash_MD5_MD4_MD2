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


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *md2 = @"dwedwaedaew";
        
        NSData *data = [md2 dataUsingEncoding:NSUTF8StringEncoding];
        
        MD_2(data);
        
        MD_2fen(data);
        
        HMac_MD5(data, @"123");
        HMac_MD5_2(data, @"123");
        
        
    }
    return 0;
}
