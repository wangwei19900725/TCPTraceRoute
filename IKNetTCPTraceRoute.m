//
//  IKNetTCPTraceRoute.m
//  IKRadar
//
//  Created by wangwei on 2022/4/29.
//
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>

#import "IKNetTCPTraceRoute.h"
#import "IKNetTimer.h"
#import "IKNetGetAddress.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#define RECV_BUF_LEN 10000
@implementation IKNetTCPTraceRoute


/**
 * 初始化
 */
- (IKNetTCPTraceRoute *)initWithMaxTTL:(int)ttl
                               size:(long)size
                            timeout:(int)timeout
                        maxAttempts:(int)attempts
{
    self = [super init];
    if (self) {
        maxTTL = ttl;
        readTimeout = timeout;
        maxAttempts = attempts;
        packetSize = size;
    }

    return self;
}

-(NSString*)resolveIP:(NSString*)host address:(struct sockaddr*)address {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s;
    
    char buf[32];
    snprintf(buf, 32, "%d", 0);
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_DEFAULT;
    
    NSString *port = @"80";
    s = getaddrinfo([host UTF8String], [port UTF8String], &hints, &result);
    if (s != 0) {
        NSLog(@"get addr info error:%s", gai_strerror(s));
        return nil;
    }
    struct addrinfo *res;
    for (res = result; res; res = res->ai_next) {
        NSLog(@"family:%d socktype;%d protocol:%d", res->ai_family, res->ai_socktype, res->ai_protocol);
    }
    
    NSString *ip = nil;
    rp = result;
    if (rp != NULL) {
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in*)rp->ai_addr;
            ip = [self IP2String:addr->sin_addr];
            memcpy(address, addr, sizeof(struct sockaddr_in));
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6*)rp->ai_addr;
            ip = [self IPV62String:addr->sin6_addr];
            memcpy(address, addr, sizeof(struct sockaddr_in6));
        }
    }
    freeaddrinfo(result);
    return ip;
}

-(NSString*)IP2String:(struct in_addr)addr {
    char buf[64] = {0};
    const char *p = inet_ntop(AF_INET, &addr, buf, 64);
    if (p) {
        return [NSString stringWithUTF8String:p];
    }
    return nil;
}

-(NSString*)IPV62String:(struct in6_addr)addr {
    char buf[64] = {0};
    const char *p = inet_ntop(AF_INET6, &addr, buf, 64);
    if (p) {
        return [NSString stringWithUTF8String:p];
    }
    return nil;
}

/**
 * 监控tranceroute 路径
 */
- (BOOL)doTraceRoute:(NSString *)host
{
    isrunning = true;
    struct sockaddr_storage addr = {0};
    NSString *hostIp = [self resolveIP:host address:(struct sockaddr*)&addr];
    NSLog(@"host:%@ ip:%@", host, hostIp);
    
    struct sockaddr* destination = (struct sockaddr*)&addr;

    int ttl = 0;
    while (ttl < maxTTL)
    {
        ttl++;
        NSMutableString *traceTTLLog = [[NSMutableString alloc] initWithCapacity:20];
        [traceTTLLog appendFormat:@"%d\t", ttl];
        long startTime;
        NSString *hostAddress = @"***";
        for (int try = 0 ; try < maxAttempts; try ++) {
            long delta = 0;
            startTime = [IKNetTimer getMicroSeconds];
            // create socket to send tcp messages
            int sendSocket = socket(destination->sa_family, SOCK_STREAM, IPPROTO_TCP);
            if (sendSocket < 0) {
                if (_delegate != nil) {
                    [_delegate tcpAppendRouteLog:@"TraceRoute>>> Could not create send socket"];
                    [_delegate tcpTraceRouteDidEnd];
                }
                return NO;
            }
            
            // create socket to receive icmp messages
            int recvSocket = socket(PF_INET, SOCK_DGRAM, IPPROTO_ICMP);
            if (recvSocket < 0) {
                if (_delegate != nil) {
                    [_delegate tcpAppendRouteLog:@"TraceRoute>>> Could not create icmp socket"];
                    [_delegate tcpTraceRouteDidEnd];
                }
                return NO;
            }
            
            // set timeout
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            
            if ((setsockopt(sendSocket, SOL_SOCKET, SO_SNDTIMEO,
                            (struct timeval *)&timeout, sizeof(struct timeval))) < 0) {
                if (_delegate != nil) {
                    [_delegate tcpAppendRouteLog:@"TraceRoute>>> Error setting socket timeout (tcp)"];
                    [_delegate tcpTraceRouteDidEnd];
                }
                return NO;
            }
           
            if ((setsockopt(recvSocket, SOL_SOCKET, SO_RCVTIMEO,
                            (struct timeval *)&timeout, sizeof(struct timeval))) < 0) {
                if (_delegate != nil) {
                    [_delegate tcpAppendRouteLog:@"TraceRoute>>> Error setting socket timeout (icmp)"];
                    [_delegate tcpTraceRouteDidEnd];
                }
                return NO;
            }
            
            // receive buffer
            char recvBuffer[RECV_BUF_LEN];
            struct sockaddr_in cli_addr;
            socklen_t cli_len = sizeof(struct sockaddr_in);
            long numBytesReceived;
            
            // set TTL in IP header
            setsockopt(sendSocket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            
            // send SYN packet (start 3-way handshake)
            errno = 0;
            connect(sendSocket, (struct sockaddr*)destination, sizeof(struct sockaddr_in));
            
            int icmpErrorReceived = 0;
            
            // TTL expired
            if (errno == EHOSTUNREACH)
            {
                while (!icmpErrorReceived)
                {
                    numBytesReceived = recvfrom(
                                                recvSocket,
                                                recvBuffer,
                                                RECV_BUF_LEN,
                                                0,
                                                (struct sockaddr *)&cli_addr,
                                                &cli_len);
                    // extract IP header
                    struct ip *ip_hdr = (struct ip *)recvBuffer;
                    
                    // extract ICMP header
                    int ipHeaderLength = 4 * ip_hdr->ip_hl;
                    struct icmp *icmp_hdr =
                    (struct icmp *)( (char*) ip_hdr + ipHeaderLength );
                    
                    int icmpMessageType = icmp_hdr->icmp_type;
                    int icmpMessageCode = icmp_hdr->icmp_code;
                    
                    // printf("ICMP type: %d code: %d\n",icmpMessageType, icmpMessageCode);
                    char display[INET_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET, &((struct sockaddr_in *)&cli_addr)->sin_addr.s_addr, display, sizeof(display));
                    hostAddress = [NSString stringWithFormat:@"%s", display];
                    
                    // TTL exceeded
                    if (icmpMessageType == ICMP_TIMXCEED
                        && icmpMessageCode == ICMP_UNREACH_NET)
                    {
                        // check if ICMP messages are related to TCP SYN packets
                        struct ip *inner_ip_hdr =
                        (struct ip *)( (char*) icmp_hdr + ICMP_MINLEN);
                        if (inner_ip_hdr->ip_p == IPPROTO_TCP)
                        {
                            icmpErrorReceived = 1;
                            delta = [IKNetTimer computeDurationSince:startTime];
                            if (try == 0) {
                                [traceTTLLog appendFormat:@"%@\t\t", hostAddress];
                            }
                            [traceTTLLog appendFormat:@"%0.3fms\t", (float)delta / 1000];
                        }
                    }
                    // port unreachable
                    else if (icmpMessageType == ICMP_UNREACH
                             && icmpMessageCode == ICMP_UNREACH_PORT)
                    {
                        if (_delegate != nil) {
    //                        _delegate tcpAppendRouteLog:[]
                        }
                        printf("--------------- traceroute terminated ---------------\n");
                    }
                }
                // case: timeout
            } else if (
                       errno == ETIMEDOUT      // socket timeout
                       || errno == EINPROGRESS // operation in progress
                       || errno == EALREADY    // consecutive timeouts
                       )
            {
                [traceTTLLog appendFormat:@"* "];
                break;
            } else {
                if (_delegate != nil) {
                    [_delegate tcpAppendRouteLog:[NSString stringWithFormat:@"%d %@ [complete]\n", ttl, hostIp]];
                    [_delegate tcpTraceRouteDidEnd];
                }
                isrunning = false;
                return YES;
            }
            
//            // case: destination reached
//            else if (errno == ECONNRESET || errno == ECONNREFUSED)
//            {
//
//            }
        }
        if (_delegate != nil) {
            [self.delegate tcpAppendRouteLog:traceTTLLog];
        }
    }
    if (_delegate != nil) {
        [_delegate tcpAppendRouteLog:[NSString stringWithFormat:@"%d %@ [complete]\n", ttl, hostIp]];
        [_delegate tcpTraceRouteDidEnd];
    }
    isrunning = false;
    return YES;
}

/**
 * 停止traceroute
 */
- (void)stopTrace
{
    @synchronized(running)
    {
        isrunning = false;
    }
}

/**
 * 检测traceroute是否在运行
 */
- (bool)isRunning
{
    return isrunning;
}

@end
