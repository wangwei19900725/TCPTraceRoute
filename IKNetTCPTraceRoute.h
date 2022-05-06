//
//  IKNetTCPTraceRoute.h
//  IKRadar
//
//  Created by wangwei on 2022/4/29.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
@protocol IKNetTCPTraceRouteDelegate <NSObject>
- (void)tcpAppendRouteLog:(NSString *)routeLog;
- (void)tcpTraceRouteDidEnd;
@end

@interface IKNetTCPTraceRoute : NSObject{
    int maxTTL;       //执行转数
    int readTimeout;  //每次发送时间的timeout
    int maxAttempts;  //每转的发送次数
    NSString *running;
    bool isrunning;
    long packetSize;  //每转发包的大小 经测试大于9216时会报错Message too long
}

@property (nonatomic, weak) id<IKNetTCPTraceRouteDelegate> delegate;

/**
 * 初始化
 */
- (IKNetTCPTraceRoute *)initWithMaxTTL:(int)ttl
                               size:(long)size
                            timeout:(int)timeout
                        maxAttempts:(int)attempts;

/**
 * 监控tranceroute 路径
 */
- (BOOL)doTraceRoute:(NSString *)host;

/**
 * 停止traceroute
 */
- (void)stopTrace;
- (bool)isRunning;

@end


NS_ASSUME_NONNULL_END
