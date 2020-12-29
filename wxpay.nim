import algorithm, hmac, macros, md5, options, parsexml, random, sequtils, streams, strutils, times, xmltree

type
  SignType* {.pure.} = enum ## 签名算法
    MD5 = "MD5",
    HMAC_SHA256 = "HMAC-SHA256"

  TradeType* {.pure.} = enum ## 交易类型
    JSAPI = "JSAPI", ## JSAPI 和小程序支付
    NATIVE = "NATIVE", ## Native 支付
    APP = "APP", ## App 支付
    MWEB = "MWEB", ## Html5 支付
    MICROPAY = "MICROPAY", ## 付款码支付

  FeeType* {.pure.} = enum ## 货币类型
    CNY = "CNY", ## 人民币

  LimitPay* {.pure.} = enum ## 指定支付方式
    NO_CREDIT = "no_credit" ## 不能使用信用卡

  ReturnCode* {.pure.} = enum ## 返回状态码
    SUCCESS = "SUCCESS",
    FAIL = "FAIL",

  ResultCode* {.pure.} = enum ## 业务结果
    SUCCESS = "SUCCESS",
    FAIL = "FAIL",

  PlaceOrderError* {.pure.} = enum ## 下单错误编码
    INVALID_REQUEST = "INVALID_REQUEST", ## 参数错误
    NOAUTH = "NOAUTH", ## 商户无此接口权限
    NOTENOUGH = "NOTENOUGH", ## 余额不足
    ORDERPAID = "ORDERPAID", ## 商户订单已支付
    ORDERCLOSED = "ORDERCLOSED", ## 订单已关闭
    SYSTEMERROR = "SYSTEMERROR", ## 系统错误
    APPID_NOT_EXIST = "APPID_NOT_EXIST", ## APPID 不存在
    MCHID_NOT_EXIST = "MCHID_NOT_EXIST", ## MCHID 不存在
    APPID_MCHID_NOT_MATCH = "APPID_MCHID_NOT_MATCH", ## APPID 和 MCHID 不匹配
    LACK_PARAMS = "LACK_PARAMS", ## 缺少参数
    OUT_TRADE_NO_USED = "OUT_TRADE_NO_USED", ## 商户订单号重复
    SIGNERROR = "SIGNERROR", ## 签名错误
    XML_FORMAT_ERROR = "XML_FORMAT_ERROR", ## XML 格式错误
    REQUIRE_POST_METHOD = "REQUIRE_POST_METHOD", ## 请使用 POST 方法
    POST_DATE_EMPTY = "POST_DATE_EMPTY", ## POST 数据为空
    NOT_UTF8 = "NOT_UTF8", ## 非 UTF-8 编码

  QueryOrderError* {.pure.} = enum ## 查询订单错误编码
    ORDERNOTEXIST = "ORDERNOTEXIST", ## 该API只能查提交支付交易返回成功的订单，请商户检查需要查询的订单号是否正确
    SYSTEMERROR = "SYSTEMERROR", ## 系统异常，请再调用发起查询

  CloseOrderError* {.pure.} = enum ## 关闭订单错误编码
    ORDERPAID = "ORDERPAID", ## 订单已支付，不能发起关单，请当作已支付的正常交易
    SYSTEMERROR = "SYSTEMERROR", ## 系统异常，请重新调用该API
    ORDERCLOSED = "ORDERCLOSED", ## 订单已关闭，无需继续调用
    SIGNERROR = "SIGNERROR", ## 请检查签名参数和方法是否都符合签名算法要求
    REQUIRE_POST_METHOD = "REQUIRE_POST_METHOD", ## 请检查请求参数是否通过post方法提交
    XML_FORMAT_ERROR = "XML_FORMAT_ERROR", ## 请检查XML参数格式是否正确

  BankType* {.pure.} = enum ## 银行类型
    ICBC_DEBIT = "ICBC_DEBIT", ## 工商银行（借记卡）
    ICBC_CREDIT = "ICBC_CREDIT", ## 工商银行（信用卡）
    ABC_DEBIT = "ABC_DEBIT", ## 农业银行（借记卡）
    ABC_CREDIT = "ABC_CREDIT", ## 农业银行（信用卡）
    PSBC_CREDIT = "PSBC_CREDIT", ## 邮储银行（信用卡）
    PSBC_DEBIT = "PSBC_DEBIT", ## 邮储银行（借记卡）
    CCB_DEBIT = "CCB_DEBIT", ## 建设银行（借记卡）
    CCB_CREDIT = "CCB_CREDIT", ## 建设银行（信用卡）
    CMB_DEBIT = "CMB_DEBIT", ## 招商银行（借记卡）
    CMB_CREDIT = "CMB_CREDIT", ## 招商银行（信用卡）
    BOC_DEBIT = "BOC_DEBIT", ## 中国银行（借记卡）
    BOC_CREDIT = "BOC_CREDIT", ## 中国银行（信用卡）
    COMM_DEBIT = "COMM_DEBIT", ## 交通银行（借记卡）
    COMM_CREDIT = "COMM_CREDIT", ## 交通银行（信用卡）
    SPDB_DEBIT = "SPDB_DEBIT", ## 浦发银行（借记卡）
    SPDB_CREDIT = "SPDB_CREDIT", ## 浦发银行（信用卡）
    GDB_DEBIT = "GDB_DEBIT", ## 广发银行（借记卡）
    GDB_CREDIT = "GDB_CREDIT", ## 广发银行（信用卡）
    CMBC_DEBIT = "CMBC_DEBIT", ## 民生银行（借记卡）
    CMBC_CREDIT = "CMBC_CREDIT", ## 民生银行（信用卡）
    PAB_DEBIT = "PAB_DEBIT", ## 平安银行（借记卡）
    PAB_CREDIT = "PAB_CREDIT", ## 平安银行（信用卡）
    CEB_DEBIT = "CEB_DEBIT", ## 光大银行（借记卡）
    CEB_CREDIT = "CEB_CREDIT", ## 光大银行（信用卡）
    CIB_DEBIT = "CIB_DEBIT", ## 兴业银行（借记卡）
    CIB_CREDIT = "CIB_CREDIT", ## 兴业银行（信用卡）
    CITIC_DEBIT = "CITIC_DEBIT", ## 中信银行（借记卡）
    CITIC_CREDIT = "CITIC_CREDIT", ## 中信银行（信用卡）
    BOSH_DEBIT = "BOSH_DEBIT", ## 上海银行（借记卡）
    BOSH_CREDIT = "BOSH_CREDIT", ## 上海银行（信用卡）
    AHRCUB_CREDIT = "AHRCUB_CREDIT", ## 安徽省农村信用社联合社（信用卡）
    AHRCUB_DEBIT = "AHRCUB_DEBIT", ## 安徽省农村信用社联合社（借记卡）
    AIB_DEBIT = "AIB_DEBIT", ## 百信银行（借记卡）
    ASCB_DEBIT = "ASCB_DEBIT", ## 鞍山银行（借记卡）
    ATRB_DEBIT = "ATRB_DEBIT", ## 盘山安泰村镇银行（借记卡）
    BCZ_CREDIT = "BCZ_CREDIT", ## 沧州银行（信用卡）
    BCZ_DEBIT = "BCZ_DEBIT", ## 沧州银行（借记卡）
    BDB_DEBIT = "BDB_DEBIT", ## 保定银行（借记卡）
    BEEB_CREDIT = "BEEB_CREDIT", ## 鄞州银行（信用卡）
    BEEB_DEBIT = "BEEB_DEBIT", ## 鄞州银行（借记卡）
    BGZB_DEBIT = "BGZB_DEBIT", ## 贵州银行（借记卡）
    BHB_CREDIT = "BHB_CREDIT", ## 河北银行（信用卡）
    BHB_DEBIT = "BHB_DEBIT", ## 河北银行（借记卡）
    BJRCB_CREDIT = "BJRCB_CREDIT", ## 北京农商行（信用卡）
    BJRCB_DEBIT = "BJRCB_DEBIT", ## 北京农商行（借记卡）
    BNC_CREDIT = "BNC_CREDIT", ## 江西银行（信用卡）
    BNC_DEBIT = "BNC_DEBIT", ## 江西银行（借记卡）
    BOB_CREDIT = "BOB_CREDIT", ## 北京银行（信用卡）
    BOB_DEBIT = "BOB_DEBIT", ## 北京银行（借记卡）
    BOBBG_CREDIT = "BOBBG_CREDIT", ## 北部湾银行（信用卡）
    BOBBG_DEBIT = "BOBBG_DEBIT", ## 北部湾银行（借记卡）
    BOCD_DEBIT = "BOCD_DEBIT", ## 成都银行（借记卡）
    BOCDB_DEBIT = "BOCDB_DEBIT", ## 承德银行（借记卡）
    BOCFB_DEBIT = "BOCFB_DEBIT", ## 中银富登村镇银行（借记卡）
    BOCTS_DEBIT = "BOCTS_DEBIT", ## 焦作中旅银行（借记卡）
    BOD_CREDIT = "BOD_CREDIT", ## 东莞银行（信用卡）
    BOD_DEBIT = "BOD_DEBIT", ## 东莞银行（借记卡）
    BOFS_DEBIT = "BOFS_DEBIT", ## 抚顺银行（借记卡）
    BOHN_DEBIT = "BOHN_DEBIT", ## 海南银行（借记卡）
    BOIMCB_CREDIT = "BOIMCB_CREDIT", ## 内蒙古银行（信用卡）
    BOIMCB_DEBIT = "BOIMCB_DEBIT", ## 内蒙古银行（借记卡）
    BOJN_DEBIT = "BOJN_DEBIT", ## 济宁银行（借记卡）
    BOJX_DEBIT = "BOJX_DEBIT", ## 嘉兴银行（借记卡）
    BOLB_DEBIT = "BOLB_DEBIT", ## 洛阳银行（借记卡）
    BOLFB_DEBIT = "BOLFB_DEBIT", ## 廊坊银行（借记卡）
    BONX_CREDIT = "BONX_CREDIT", ## 宁夏银行（信用卡）
    BONX_DEBIT = "BONX_DEBIT", ## 宁夏银行（借记卡）
    BOPDS_DEBIT = "BOPDS_DEBIT", ## 平顶山银行（借记卡）
    BOPJ_DEBIT = "BOPJ_DEBIT", ## 盘锦银行（借记卡）
    BOQHB_CREDIT = "BOQHB_CREDIT", ## 青海银行（信用卡）
    BOQHB_DEBIT = "BOQHB_DEBIT", ## 青海银行（借记卡）
    BOSXB_DEBIT = "BOSXB_DEBIT", ## 绍兴银行（借记卡）
    BOSZS_DEBIT = "BOSZS_DEBIT", ## 石嘴山银行（借记卡）
    BOTSB_DEBIT = "BOTSB_DEBIT", ## 唐山银行（借记卡）
    BOZ_CREDIT = "BOZ_CREDIT", ## 张家口银行（信用卡）
    BOZ_DEBIT = "BOZ_DEBIT", ## 张家口银行（借记卡）
    BSB_CREDIT = "BSB_CREDIT", ## 包商银行（信用卡）
    BSB_DEBIT = "BSB_DEBIT", ## 包商银行（借记卡）
    BYK_DEBIT = "BYK_DEBIT", ## 营口银行（借记卡）
    CBHB_DEBIT = "CBHB_DEBIT", ## 渤海银行（借记卡）
    CCAB_CREDIT = "CCAB_CREDIT", ## 长安银行（信用卡）
    CCAB_DEBIT = "CCAB_DEBIT", ## 长安银行（借记卡）
    CDRCB_DEBIT = "CDRCB_DEBIT", ## 成都农商银行（借记卡）
    CITIB_CREDIT = "CITIB_CREDIT", ## 花旗银行（信用卡）
    CITIB_DEBIT = "CITIB_DEBIT", ## 花旗银行（借记卡）
    CJCCB_DEBIT = "CJCCB_DEBIT", ## 江苏长江商业银行（借记卡）
    CQB_CREDIT = "CQB_CREDIT", ## 重庆银行（信用卡）
    CQB_DEBIT = "CQB_DEBIT", ## 重庆银行（借记卡）
    CQRCB_CREDIT = "CQRCB_CREDIT", ## 重庆农村商业银行（信用卡）
    CQRCB_DEBIT = "CQRCB_DEBIT", ## 重庆农村商业银行（借记卡）
    CQTGB_DEBIT = "CQTGB_DEBIT", ## 重庆三峡银行（借记卡）
    CRB_CREDIT = "CRB_CREDIT", ## 珠海华润银行（信用卡）
    CRB_DEBIT = "CRB_DEBIT", ## 珠海华润银行（借记卡）
    CSCB_CREDIT = "CSCB_CREDIT", ## 长沙银行（信用卡）
    CSCB_DEBIT = "CSCB_DEBIT", ## 长沙银行（借记卡）
    CSRCB_CREDIT = "CSRCB_CREDIT", ## 常熟农商银行（信用卡）
    CSRCB_DEBIT = "CSRCB_DEBIT", ## 常熟农商银行（借记卡）
    CSXB_DEBIT = "CSXB_DEBIT", ## 三湘银行（借记卡）
    CYCB_CREDIT = "CYCB_CREDIT", ## 朝阳银行（信用卡）
    CYCB_DEBIT = "CYCB_DEBIT", ## 朝阳银行（借记卡）
    CZB_CREDIT = "CZB_CREDIT", ## 浙商银行（信用卡）
    CZB_DEBIT = "CZB_DEBIT", ## 浙商银行（借记卡）
    CZCB_CREDIT = "CZCB_CREDIT", ## 稠州银行（信用卡）
    CZCB_DEBIT = "CZCB_DEBIT", ## 稠州银行（借记卡）
    CZCCB_DEBIT = "CZCCB_DEBIT", ## 长治银行（借记卡）
    DANDONGB_CREDIT = "DANDONGB_CREDIT", ## 丹东银行（信用卡）
    DANDONGB_DEBIT = "DANDONGB_DEBIT", ## 丹东银行（借记卡）
    DBSB_DEBIT = "DBSB_DEBIT", ## 星展银行（借记卡）
    DCSFRB_DEBIT = "DCSFRB_DEBIT", ## 大城舜丰村镇银行（借记卡）
    DHDYB_DEBIT = "DHDYB_DEBIT", ## 德惠敦银村镇银行（借记卡）
    DHRB_DEBIT = "DHRB_DEBIT", ## 调兵山惠民村镇银行（借记卡）
    DLB_CREDIT = "DLB_CREDIT", ## 大连银行（信用卡）
    DLB_DEBIT = "DLB_DEBIT", ## 大连银行（借记卡）
    DLRCB_DEBIT = "DLRCB_DEBIT", ## 大连农商行（借记卡）
    DRCB_CREDIT = "DRCB_CREDIT", ## 东莞农商银行（信用卡）
    DRCB_DEBIT = "DRCB_DEBIT", ## 东莞农商银行（借记卡）
    DSB_DEBIT = "DSB_DEBIT", ## 大新银行（借记卡）
    DTCCB_DEBIT = "DTCCB_DEBIT", ## 大同银行（借记卡）
    DYB_CREDIT = "DYB_CREDIT", ## 东营银行（信用卡）
    DYB_DEBIT = "DYB_DEBIT", ## 东营银行（借记卡）
    DYCCB_DEBIT = "DYCCB_DEBIT", ## 长城华西银行（借记卡）
    DYLSB_DEBIT = "DYLSB_DEBIT", ## 东营莱商村镇银行（借记卡）
    DZB_DEBIT = "DZB_DEBIT", ## 德州银行（借记卡）
    DZCCB_DEBIT = "DZCCB_DEBIT", ## 达州银行（借记卡）
    EDRB_DEBIT = "EDRB_DEBIT", ## 鼎业村镇银行（借记卡）
    ESUNB_DEBIT = "ESUNB_DEBIT", ## 玉山银行（借记卡）
    FBB_DEBIT = "FBB_DEBIT", ## 富邦华一银行（借记卡）
    FDB_CREDIT = "FDB_CREDIT", ## 富滇银行（信用卡）
    FDB_DEBIT = "FDB_DEBIT", ## 富滇银行（借记卡）
    FJHXB_CREDIT = "FJHXB_CREDIT", ## 福建海峡银行（信用卡）
    FJHXB_DEBIT = "FJHXB_DEBIT", ## 福建海峡银行（借记卡）
    FJNX_CREDIT = "FJNX_CREDIT", ## 福建农信银行（信用卡）
    FJNX_DEBIT = "FJNX_DEBIT", ## 福建农信银行（借记卡）
    FUXINB_CREDIT = "FUXINB_CREDIT", ## 阜新银行（信用卡）
    FUXINB_DEBIT = "FUXINB_DEBIT", ## 阜新银行（借记卡）
    FXLZB_DEBIT = "FXLZB_DEBIT", ## 费县梁邹村镇银行（借记卡）
    GADRB_DEBIT = "GADRB_DEBIT", ## 贵安新区发展村镇银行（借记卡）
    GDHX_DEBIT = "GDHX_DEBIT", ## 广东华兴银行（借记卡）
    GDNYB_CREDIT = "GDNYB_CREDIT", ## 南粤银行（信用卡）
    GDNYB_DEBIT = "GDNYB_DEBIT", ## 南粤银行（借记卡）
    GDRCU_DEBIT = "GDRCU_DEBIT", ## 广东农信银行（借记卡）
    GLB_CREDIT = "GLB_CREDIT", ## 桂林银行（信用卡）
    GLB_DEBIT = "GLB_DEBIT", ## 桂林银行（借记卡）
    GLGMCB_DEBIT = "GLGMCB_DEBIT", ## 桂林国民村镇银行（借记卡）
    GRCB_CREDIT = "GRCB_CREDIT", ## 广州农商银行（信用卡）
    GRCB_DEBIT = "GRCB_DEBIT", ## 广州农商银行（借记卡）
    GSB_DEBIT = "GSB_DEBIT", ## 甘肃银行（借记卡）
    GSNX_DEBIT = "GSNX_DEBIT", ## 甘肃农信（借记卡）
    GSRB_DEBIT = "GSRB_DEBIT", ## 广阳舜丰村镇银行（借记卡）
    GXNX_CREDIT = "GXNX_CREDIT", ## 广西农信（信用卡）
    GXNX_DEBIT = "GXNX_DEBIT", ## 广西农信（借记卡）
    GYCB_CREDIT = "GYCB_CREDIT", ## 贵阳银行（信用卡）
    GYCB_DEBIT = "GYCB_DEBIT", ## 贵阳银行（借记卡）
    GZCB_CREDIT = "GZCB_CREDIT", ## 广州银行（信用卡）
    GZCB_DEBIT = "GZCB_DEBIT", ## 广州银行（借记卡）
    GZCCB_CREDIT = "GZCCB_CREDIT", ## 赣州银行（信用卡）
    GZCCB_DEBIT = "GZCCB_DEBIT", ## 赣州银行（借记卡）
    GZNX_DEBIT = "GZNX_DEBIT", ## 贵州农信（借记卡）
    HAINNX_CREDIT = "HAINNX_CREDIT", ## 海南农信（信用卡）
    HAINNX_DEBIT = "HAINNX_DEBIT", ## 海南农信（借记卡）
    HANAB_DEBIT = "HANAB_DEBIT", ## 韩亚银行（借记卡）
    HBCB_CREDIT = "HBCB_CREDIT", ## 湖北银行（信用卡）
    HBCB_DEBIT = "HBCB_DEBIT", ## 湖北银行（借记卡）
    HBNX_CREDIT = "HBNX_CREDIT", ## 湖北农信（信用卡）
    HBNX_DEBIT = "HBNX_DEBIT", ## 湖北农信（借记卡）
    HDCB_DEBIT = "HDCB_DEBIT", ## 邯郸银行（借记卡）
    HEBNX_DEBIT = "HEBNX_DEBIT", ## 河北农信（借记卡）
    HFB_CREDIT = "HFB_CREDIT", ## 恒丰银行（信用卡）
    HFB_DEBIT = "HFB_DEBIT", ## 恒丰银行（借记卡）
    HKB_CREDIT = "HKB_CREDIT", ## 汉口银行（信用卡）
    HKB_DEBIT = "HKB_DEBIT", ## 汉口银行（借记卡）
    HKBEA_CREDIT = "HKBEA_CREDIT", ## 东亚银行（信用卡）
    HKBEA_DEBIT = "HKBEA_DEBIT", ## 东亚银行（借记卡）
    HKUB_DEBIT = "HKUB_DEBIT", ## 海口联合农商银行（借记卡）
    HLDCCB_DEBIT = "HLDCCB_DEBIT", ## 葫芦岛银行（借记卡）
    HLDYB_DEBIT = "HLDYB_DEBIT", ## 和龙敦银村镇银行（借记卡）
    HLJRCUB_DEBIT = "HLJRCUB_DEBIT", ## 黑龙江农信社（借记卡）
    HMCCB_DEBIT = "HMCCB_DEBIT", ## 哈密银行（借记卡）
    HNNX_DEBIT = "HNNX_DEBIT", ## 河南农信（借记卡）
    HRBB_CREDIT = "HRBB_CREDIT", ## 哈尔滨银行（信用卡）
    HRBB_DEBIT = "HRBB_DEBIT", ## 哈尔滨银行（借记卡）
    HRCB_DEBIT = "HRCB_DEBIT", ## 保德慧融村镇银行（借记卡）
    HRXJB_CREDIT = "HRXJB_CREDIT", ## 华融湘江银行（信用卡）
    HRXJB_DEBIT = "HRXJB_DEBIT", ## 华融湘江银行（借记卡）
    HSB_CREDIT = "HSB_CREDIT", ## 徽商银行（信用卡）
    HSB_DEBIT = "HSB_DEBIT", ## 徽商银行（借记卡）
    HSBC_DEBIT = "HSBC_DEBIT", ## 恒生银行（借记卡）
    HSBCC_CREDIT = "HSBCC_CREDIT", ## 汇丰银行（信用卡）
    HSBCC_DEBIT = "HSBCC_DEBIT", ## 汇丰银行（借记卡）
    HSCB_DEBIT = "HSCB_DEBIT", ## 衡水银行（借记卡）
    HUIHEB_DEBIT = "HUIHEB_DEBIT", ## 新疆汇和银行（借记卡）
    HUNNX_DEBIT = "HUNNX_DEBIT", ## 湖南农信（借记卡）
    HUSRB_DEBIT = "HUSRB_DEBIT", ## 湖商村镇银行（借记卡）
    HXB_CREDIT = "HXB_CREDIT", ## 华夏银行（信用卡）
    HXB_DEBIT = "HXB_DEBIT", ## 华夏银行（借记卡）
    HZB_CREDIT = "HZB_CREDIT", ## 杭州银行（信用卡）
    HZB_DEBIT = "HZB_DEBIT", ## 杭州银行（借记卡）
    HZCCB_DEBIT = "HZCCB_DEBIT", ## 湖州银行（借记卡）
    IBKB_DEBIT = "IBKB_DEBIT", ## 企业银行（借记卡）
    JCB_DEBIT = "JCB_DEBIT", ## 晋城银行（借记卡）
    JCBK_CREDIT = "JCBK_CREDIT", ## 晋城银行（信用卡）
    JDHDB_DEBIT = "JDHDB_DEBIT", ## 上海嘉定洪都村镇银行（借记卡）
    JDZCCB_DEBIT = "JDZCCB_DEBIT", ## 景德镇市商业银行（借记卡）
    JHCCB_CREDIT = "JHCCB_CREDIT", ## 金华银行（信用卡）
    JHCCB_DEBIT = "JHCCB_DEBIT", ## 金华银行（借记卡）
    JJCCB_CREDIT = "JJCCB_CREDIT", ## 九江银行（信用卡）
    JJCCB_DEBIT = "JJCCB_DEBIT", ## 九江银行（借记卡）
    JLB_CREDIT = "JLB_CREDIT", ## 吉林银行（信用卡）
    JLB_DEBIT = "JLB_DEBIT", ## 吉林银行（借记卡）
    JLNX_DEBIT = "JLNX_DEBIT", ## 吉林农信（借记卡）
    JNRCB_CREDIT = "JNRCB_CREDIT", ## 江南农商行（信用卡）
    JNRCB_DEBIT = "JNRCB_DEBIT", ## 江南农商行（借记卡）
    JRCB_CREDIT = "JRCB_CREDIT", ## 江阴农商行（信用卡）
    JRCB_DEBIT = "JRCB_DEBIT", ## 江阴农商行（借记卡）
    JSB_CREDIT = "JSB_CREDIT", ## 江苏银行（信用卡）
    JSB_DEBIT = "JSB_DEBIT", ## 江苏银行（借记卡）
    JSHB_CREDIT = "JSHB_CREDIT", ## 晋商银行（信用卡）
    JSHB_DEBIT = "JSHB_DEBIT", ## 晋商银行（借记卡）
    JSNX_CREDIT = "JSNX_CREDIT", ## 江苏农信（信用卡）
    JSNX_DEBIT = "JSNX_DEBIT", ## 江苏农信（借记卡）
    JUFENGB_DEBIT = "JUFENGB_DEBIT", ## 临朐聚丰村镇银行（借记卡）
    JXB_DEBIT = "JXB_DEBIT", ## 西昌金信村镇银行（借记卡）
    JXNXB_DEBIT = "JXNXB_DEBIT", ## 江西农信（借记卡）
    JZB_CREDIT = "JZB_CREDIT", ## 晋中银行（信用卡）
    JZB_DEBIT = "JZB_DEBIT", ## 晋中银行（借记卡）
    JZCB_CREDIT = "JZCB_CREDIT", ## 锦州银行（信用卡）
    JZCB_DEBIT = "JZCB_DEBIT", ## 锦州银行（借记卡）
    KCBEB_DEBIT = "KCBEB_DEBIT", ## 天津金城银行（借记卡）
    KLB_CREDIT = "KLB_CREDIT", ## 昆仑银行（信用卡）
    KLB_DEBIT = "KLB_DEBIT", ## 昆仑银行（借记卡）
    KRCB_DEBIT = "KRCB_DEBIT", ## 昆山农商（借记卡）
    KSHB_DEBIT = "KSHB_DEBIT", ## 梅州客商银行（借记卡）
    KUERLECB_DEBIT = "KUERLECB_DEBIT", ## 库尔勒市商业银行（借记卡）
    LCYRB_DEBIT = "LCYRB_DEBIT", ## 陵城圆融村镇银行（借记卡）
    LICYRB_DEBIT = "LICYRB_DEBIT", ## 历城圆融村镇银行（借记卡）
    LJB_DEBIT = "LJB_DEBIT", ## 龙江银行（借记卡）
    LLB_DEBIT = "LLB_DEBIT", ## 山东兰陵村镇银行（借记卡）
    LLHZCB_DEBIT = "LLHZCB_DEBIT", ## 柳林汇泽村镇银行（借记卡）
    LNNX_DEBIT = "LNNX_DEBIT", ## 辽宁农信（借记卡）
    LPCB_DEBIT = "LPCB_DEBIT", ## 凉山州商业银行（借记卡）
    LPSBLVB_DEBIT = "LPSBLVB_DEBIT", ## 钟山凉都村镇银行（借记卡）
    LSB_CREDIT = "LSB_CREDIT", ## 临商银行（信用卡）
    LSB_DEBIT = "LSB_DEBIT", ## 临商银行（借记卡）
    LSCCB_DEBIT = "LSCCB_DEBIT", ## 乐山市商业银行（借记卡）
    LUZB_DEBIT = "LUZB_DEBIT", ## 柳州银行（借记卡）
    LWB_DEBIT = "LWB_DEBIT", ## 莱商银行（借记卡）
    LYYHB_DEBIT = "LYYHB_DEBIT", ## 辽阳银行（借记卡）
    LZB_CREDIT = "LZB_CREDIT", ## 兰州银行（信用卡）
    LZB_DEBIT = "LZB_DEBIT", ## 兰州银行（借记卡）
    LZCCB_DEBIT = "LZCCB_DEBIT", ## 泸州市商业银行（借记卡）
    MHBRB_DEBIT = "MHBRB_DEBIT", ## 闵行上银村镇银行（借记卡）
    MINTAIB_CREDIT = "MINTAIB_CREDIT", ## 民泰银行（信用卡）
    MINTAIB_DEBIT = "MINTAIB_DEBIT", ## 民泰银行（借记卡）
    MPJDRB_DEBIT = "MPJDRB_DEBIT", ## 牟平胶东村镇银行（借记卡）
    MYCCB_DEBIT = "MYCCB_DEBIT", ## 绵阳市商业银行（借记卡）
    NBCB_CREDIT = "NBCB_CREDIT", ## 宁波银行（信用卡）
    NBCB_DEBIT = "NBCB_DEBIT", ## 宁波银行（借记卡）
    NCB_DEBIT = "NCB_DEBIT", ## 宁波通商银行（借记卡）
    NCBCB_DEBIT = "NCBCB_DEBIT", ## 南洋商业银行（借记卡）
    NCCB_DEBIT = "NCCB_DEBIT", ## 四川天府银行（借记卡）
    NJCB_CREDIT = "NJCB_CREDIT", ## 南京银行（信用卡）
    NJCB_DEBIT = "NJCB_DEBIT", ## 南京银行（借记卡）
    NJJDRB_DEBIT = "NJJDRB_DEBIT", ## 宁津胶东村镇银行（借记卡）
    NJXLRB_DEBIT = "NJXLRB_DEBIT", ## 内江兴隆村镇银行（借记卡）
    NMGNX_DEBIT = "NMGNX_DEBIT", ## 内蒙古农信（借记卡）
    NNGMB_DEBIT = "NNGMB_DEBIT", ## 南宁江南国民村镇银行（借记卡）
    NUB_DEBIT = "NUB_DEBIT", ## 辽宁振兴银行（借记卡）
    NYCCB_DEBIT = "NYCCB_DEBIT", ## 南阳村镇银行（借记卡）
    OCBCWHCB_DEBIT = "OCBCWHCB_DEBIT", ## 华侨永亨银行（借记卡）
    OHVB_DEBIT = "OHVB_DEBIT", ## 鄂托克旗汇泽村镇银行（借记卡）
    ORDOSB_CREDIT = "ORDOSB_CREDIT", ## 鄂尔多斯银行（信用卡）
    ORDOSB_DEBIT = "ORDOSB_DEBIT", ## 鄂尔多斯银行（借记卡）
    PBDLRB_DEBIT = "PBDLRB_DEBIT", ## 平坝鼎立村镇银行（借记卡）
    PJDWHFB_DEBIT = "PJDWHFB_DEBIT", ## 大洼恒丰村镇银行（借记卡）
    PJJYRB_DEBIT = "PJJYRB_DEBIT", ## 浦江嘉银村镇银行（借记卡）
    PZHCCB_DEBIT = "PZHCCB_DEBIT", ## 攀枝花银行（借记卡）
    QDCCB_CREDIT = "QDCCB_CREDIT", ## 青岛银行（信用卡）
    QDCCB_DEBIT = "QDCCB_DEBIT", ## 青岛银行（借记卡）
    QHDB_DEBIT = "QHDB_DEBIT", ## 秦皇岛银行（借记卡）
    QHJDRB_DEBIT = "QHJDRB_DEBIT", ## 齐河胶东村镇银行（借记卡）
    QHNX_DEBIT = "QHNX_DEBIT", ## 青海农信（借记卡）
    QJSYB_DEBIT = "QJSYB_DEBIT", ## 衢江上银村镇银行（借记卡）
    QLB_CREDIT = "QLB_CREDIT", ## 齐鲁银行（信用卡）
    QLB_DEBIT = "QLB_DEBIT", ## 齐鲁银行（借记卡）
    QLVB_DEBIT = "QLVB_DEBIT", ## 青隆村镇银行（借记卡）
    QSB_CREDIT = "QSB_CREDIT", ## 齐商银行（信用卡）
    QSB_DEBIT = "QSB_DEBIT", ## 齐商银行（借记卡）
    QZCCB_CREDIT = "QZCCB_CREDIT", ## 泉州银行（信用卡）
    QZCCB_DEBIT = "QZCCB_DEBIT", ## 泉州银行（借记卡）
    RHCB_DEBIT = "RHCB_DEBIT", ## 长子县融汇村镇银行（借记卡）
    RQCZB_DEBIT = "RQCZB_DEBIT", ## 任丘村镇银行（借记卡）
    RXYHB_DEBIT = "RXYHB_DEBIT", ## 瑞信村镇银行（借记卡）
    RZB_DEBIT = "RZB_DEBIT", ## 日照银行（借记卡）
    SCB_CREDIT = "SCB_CREDIT", ## 渣打银行（信用卡）
    SCB_DEBIT = "SCB_DEBIT", ## 渣打银行（借记卡）
    SCNX_DEBIT = "SCNX_DEBIT", ## 四川农信（借记卡）
    SDEB_CREDIT = "SDEB_CREDIT", ## 顺德农商行（信用卡）
    SDEB_DEBIT = "SDEB_DEBIT", ## 顺德农商行（借记卡）
    SDRCU_DEBIT = "SDRCU_DEBIT", ## 山东农信（借记卡）
    SHHJB_DEBIT = "SHHJB_DEBIT", ## 商河汇金村镇银行（借记卡）
    SHINHAN_DEBIT = "SHINHAN_DEBIT", ## 新韩银行（借记卡）
    SHRB_DEBIT = "SHRB_DEBIT", ## 上海华瑞银行（借记卡）
    SJB_CREDIT = "SJB_CREDIT", ## 盛京银行（信用卡）
    SJB_DEBIT = "SJB_DEBIT", ## 盛京银行（借记卡）
    SNB_DEBIT = "SNB_DEBIT", ## 苏宁银行（借记卡）
    SNCCB_DEBIT = "SNCCB_DEBIT", ## 遂宁银行（借记卡）
    SPDYB_DEBIT = "SPDYB_DEBIT", ## 四平铁西敦银村镇银行（借记卡）
    SRB_DEBIT = "SRB_DEBIT", ## 上饶银行（借记卡）
    SRCB_CREDIT = "SRCB_CREDIT", ## 上海农商银行（信用卡）
    SRCB_DEBIT = "SRCB_DEBIT", ## 上海农商银行（借记卡）
    SUZB_CREDIT = "SUZB_CREDIT", ## 苏州银行（信用卡）
    SUZB_DEBIT = "SUZB_DEBIT", ## 苏州银行（借记卡）
    SXNX_DEBIT = "SXNX_DEBIT", ## 山西农信（借记卡）
    SXXH_DEBIT = "SXXH_DEBIT", ## 陕西信合（借记卡）
    SZRCB_CREDIT = "SZRCB_CREDIT", ## 深圳农商银行（信用卡）
    SZRCB_DEBIT = "SZRCB_DEBIT", ## 深圳农商银行（借记卡）
    TACCB_CREDIT = "TACCB_CREDIT", ## 泰安银行（信用卡）
    TACCB_DEBIT = "TACCB_DEBIT", ## 泰安银行（借记卡）
    TCRCB_DEBIT = "TCRCB_DEBIT", ## 太仓农商行（借记卡）
    TJB_CREDIT = "TJB_CREDIT", ## 天津银行（信用卡）
    TJB_DEBIT = "TJB_DEBIT", ## 天津银行（借记卡）
    TJBHB_CREDIT = "TJBHB_CREDIT", ## 天津滨海农商行（信用卡）
    TJBHB_DEBIT = "TJBHB_DEBIT", ## 天津滨海农商行（借记卡）
    TJHMB_DEBIT = "TJHMB_DEBIT", ## 天津华明村镇银行（借记卡）
    TJNHVB_DEBIT = "TJNHVB_DEBIT", ## 天津宁河村镇银行（借记卡）
    TLB_DEBIT = "TLB_DEBIT", ## 铁岭银行（借记卡）
    TLVB_DEBIT = "TLVB_DEBIT", ## 铁岭新星村镇银行（借记卡）
    TMDYB_DEBIT = "TMDYB_DEBIT", ## 图们敦银村镇银行（借记卡）
    TRCB_CREDIT = "TRCB_CREDIT", ## 天津农商（信用卡）
    TRCB_DEBIT = "TRCB_DEBIT", ## 天津农商（借记卡）
    TZB_CREDIT = "TZB_CREDIT", ## 台州银行（信用卡）
    TZB_DEBIT = "TZB_DEBIT", ## 台州银行（借记卡）
    UOB_DEBIT = "UOB_DEBIT", ## 大华银行（借记卡）
    URB_DEBIT = "URB_DEBIT", ## 联合村镇银行（借记卡）
    VBCB_DEBIT = "VBCB_DEBIT", ## 村镇银行（借记卡）
    WACZB_DEBIT = "WACZB_DEBIT", ## 武安村镇银行（借记卡）
    WB_DEBIT = "WB_DEBIT", ## 友利银行（借记卡）
    WEB_DEBIT = "WEB_DEBIT", ## 微众银行（借记卡）
    WEGOB_DEBIT = "WEGOB_DEBIT", ## 蓝海银行（借记卡）
    WFB_CREDIT = "WFB_CREDIT", ## 潍坊银行（信用卡）
    WFB_DEBIT = "WFB_DEBIT", ## 潍坊银行（借记卡）
    WHB_CREDIT = "WHB_CREDIT", ## 威海商业银行（信用卡）
    WHB_DEBIT = "WHB_DEBIT", ## 威海商业银行（借记卡）
    WHRC_CREDIT = "WHRC_CREDIT", ## 武汉农商行（信用卡）
    WHRC_DEBIT = "WHRC_DEBIT", ## 武汉农商行（借记卡）
    WHRYVB_DEBIT = "WHRYVB_DEBIT", ## 芜湖圆融村镇银行（借记卡）
    WJRCB_CREDIT = "WJRCB_CREDIT", ## 吴江农商行（信用卡）
    WJRCB_DEBIT = "WJRCB_DEBIT", ## 吴江农商行（借记卡）
    WLMQB_CREDIT = "WLMQB_CREDIT", ## 乌鲁木齐银行（信用卡）
    WLMQB_DEBIT = "WLMQB_DEBIT", ## 乌鲁木齐银行（借记卡）
    WRCB_CREDIT = "WRCB_CREDIT", ## 无锡农商行（信用卡）
    WRCB_DEBIT = "WRCB_DEBIT", ## 无锡农商行（借记卡）
    WUHAICB_DEBIT = "WUHAICB_DEBIT", ## 乌海银行（借记卡）
    WZB_CREDIT = "WZB_CREDIT", ## 温州银行（信用卡）
    WZB_DEBIT = "WZB_DEBIT", ## 温州银行（借记卡）
    WZMSB_DEBIT = "WZMSB_DEBIT", ## 温州民商（借记卡）
    XAB_CREDIT = "XAB_CREDIT", ## 西安银行（信用卡）
    XAB_DEBIT = "XAB_DEBIT", ## 西安银行（借记卡）
    XCXPB_DEBIT = "XCXPB_DEBIT", ## 许昌新浦村镇银行（借记卡）
    XHB_DEBIT = "XHB_DEBIT", ## 大连鑫汇村镇银行（借记卡）
    XHNMB_DEBIT = "XHNMB_DEBIT", ## 安顺西航南马村镇银行（借记卡）
    XIB_DEBIT = "XIB_DEBIT", ## 厦门国际银行（借记卡）
    XINANB_DEBIT = "XINANB_DEBIT", ## 安徽新安银行（借记卡）
    XJB_DEBIT = "XJB_DEBIT", ## 新疆银行（借记卡）
    XJJDRB_DEBIT = "XJJDRB_DEBIT", ## 夏津胶东村镇银行（借记卡）
    XJRCCB_DEBIT = "XJRCCB_DEBIT", ## 新疆农信银行（借记卡）
    XMCCB_CREDIT = "XMCCB_CREDIT", ## 厦门银行（信用卡）
    XMCCB_DEBIT = "XMCCB_DEBIT", ## 厦门银行（借记卡）
    XRTB_DEBIT = "XRTB_DEBIT", ## 元氏信融村镇银行（借记卡）
    XTB_CREDIT = "XTB_CREDIT", ## 邢台银行（信用卡）
    XTB_DEBIT = "XTB_DEBIT", ## 邢台银行（借记卡）
    XWB_DEBIT = "XWB_DEBIT", ## 新网银行（借记卡）
    XXCB_DEBIT = "XXCB_DEBIT", ## 新乡银行（借记卡）
    XXHZCB_DEBIT = "XXHZCB_DEBIT", ## 兴县汇泽村镇银行（借记卡）
    XXRB_DEBIT = "XXRB_DEBIT", ## 新乡新兴村镇银行（借记卡）
    XYPQZYCB_DEBIT = "XYPQZYCB_DEBIT", ## 信阳平桥中原村镇银行（借记卡）
    XZB_DEBIT = "XZB_DEBIT", ## 西藏银行（借记卡）
    YACCB_DEBIT = "YACCB_DEBIT", ## 雅安市商业银行（借记卡）
    YBCCB_DEBIT = "YBCCB_DEBIT", ## 宜宾商业银行（借记卡）
    YKCB_DEBIT = "YKCB_DEBIT", ## 营口沿海银行（借记卡）
    YLB_DEBIT = "YLB_DEBIT", ## 亿联银行（借记卡）
    YNHTB_CREDIT = "YNHTB_CREDIT", ## 云南红塔银行（信用卡）
    YNHTB_DEBIT = "YNHTB_DEBIT", ## 云南红塔银行（借记卡）
    YNRCCB_CREDIT = "YNRCCB_CREDIT", ## 云南农信（信用卡）
    YNRCCB_DEBIT = "YNRCCB_DEBIT", ## 云南农信（借记卡）
    YQCCB_DEBIT = "YQCCB_DEBIT", ## 阳泉市商业银行（借记卡）
    YQMYRB_DEBIT = "YQMYRB_DEBIT", ## 玉泉蒙银村镇银行（借记卡）
    YRRCB_CREDIT = "YRRCB_CREDIT", ## 黄河农商银行（信用卡）
    YRRCB_DEBIT = "YRRCB_DEBIT", ## 黄河农商银行（借记卡）
    YTB_DEBIT = "YTB_DEBIT", ## 烟台银行（借记卡）
    YYBSCB_DEBIT = "YYBSCB_DEBIT", ## 沂源博商村镇银行（借记卡）
    ZCRB_DEBIT = "ZCRB_DEBIT", ## 遵义新蒲长征村镇银行（借记卡）
    ZGB_DEBIT = "ZGB_DEBIT", ## 自贡银行（借记卡）
    ZGCB_DEBIT = "ZGCB_DEBIT", ## 北京中关村银行（借记卡）
    ZHCB_DEBIT = "ZHCB_DEBIT", ## 庄河汇通村镇银行（借记卡）
    ZHQYTB_DEBIT = "ZHQYTB_DEBIT", ## 沾化青云村镇银行（借记卡）
    ZJB_DEBIT = "ZJB_DEBIT", ## 紫金农商银行（借记卡）
    ZJLXRB_DEBIT = "ZJLXRB_DEBIT", ## 兰溪越商银行（借记卡）
    ZJRCUB_CREDIT = "ZJRCUB_CREDIT", ## 浙江农信（信用卡）
    ZJRCUB_DEBIT = "ZJRCUB_DEBIT", ## 浙江农信（借记卡）
    ZJTLCB_CREDIT = "ZJTLCB_CREDIT", ## 浙江泰隆银行（信用卡）
    ZJTLCB_DEBIT = "ZJTLCB_DEBIT", ## 浙江泰隆银行（借记卡）
    ZRCB_CREDIT = "ZRCB_CREDIT", ## 张家港农商行（信用卡）
    ZRCB_DEBIT = "ZRCB_DEBIT", ## 张家港农商行（借记卡）
    ZSXKCCB_DEBIT = "ZSXKCCB_DEBIT", ## 中山小榄村镇银行（借记卡）
    ZYB_CREDIT = "ZYB_CREDIT", ## 中原银行（信用卡）
    ZYB_DEBIT = "ZYB_DEBIT", ## 中原银行（借记卡）
    ZZB_CREDIT = "ZZB_CREDIT", ## 郑州银行（信用卡）
    ZZB_DEBIT = "ZZB_DEBIT", ## 郑州银行（借记卡）
    ZZCCB_DEBIT = "ZZCCB_DEBIT", ## 枣庄银行（借记卡）
    DINERSCLUD = "DINERSCLUD", ## DINERSCLUD
    MASTERCARD = "MASTERCARD", ## MASTERCARD
    VISA = "VISA", ## VISA
    AMERICANEXPRESS = "AMERICANEXPRESS", ## AMERICANEXPRESS
    DISCOVER = "DISCOVER", ## DISCOVER
    OTHERS = "OTHERS", ## 其他（银行卡以外）

  CouponType* {.pure.} = enum ## 代金券类型
    CASH = "CASH", ## 充值代金券
    NO_CASH = "NO_CASH", ## 非充值代金券

  TradeState* {.pure.} = enum ## 交易状态
    SUCCESS = "SUCCESS", ## 支付成功
    REFUND = "REFUND", ## 转入退款
    NOTPAY = "NOTPAY", ## 未支付
    CLOSED = "CLOSED", ## 已关闭
    REVOKED = "REVOKED", ## 已撤销(刷卡支付)
    USERPAYING = "USERPAYING", ## 用户支付中
    PAYERROR = "PAYERROR", ## 支付失败(其他原因，如银行返回失败)

  ResponseBody* = ref object of RootObj ## 响应内容
    return_code*: ReturnCode
    return_msg*: Option[string]

  PlaceOrderRequestBody* = ref object ## 下单请求内容
    appid*: string ## 应用 ID
    mch_id*: string  ## 商户号
    device_info*: Option[string] ## 终端设备号(门店号或收银设备ID)，默认"WEB"，不长于32位。
    nonce_str*: string ## 随即字符串，不长于32位。
    sign*: string ## 签名
    sign_type*: Option[SignType] ## 签名类型，默认 MD5
    body*: string ## 商品描述交易字段，格式：应用市场APP名称-实际商品名称，比如：
                  ## 天天爱消除-游戏充值
    detail*: Option[string] ## 商品详细描述，对于使用单品优惠的商户，该字段必须参照
                            ## https://pay.weixin.qq.com/wiki/doc/api/danpin.php?chapter=9_102&index=2
    attach*: Option[string] ## 附加数据，在查询API和支付通知中原样返回，该字段主要用于商户携带订单的
                            ## 自定义数据，不长于 127 位
    out_trade_no*: string ## 商户系统内部订单号，要求32个字符以内，只能是数字、大小写字母_-|*，
                          ## 且在同一个商户下唯一。
    fee_type*: Option[FeeType] ## 符合 ISO 4217 标准的三位字母代码，默认 CNY。
    total_fee*: int ## 订单总金额，单位为分。
    spbill_create_ip*: string ## 调用微信支付 API 的机器IP。
    time_start*: Option[DateTime] ## 订单生成时间
    time_expire*: Option[DateTime] ## 订单失效时间
    goods_tag*: Option[string] ## 订单优惠标记，代金券或立减优惠功能的参数，详见
                               ## https://pay.weixin.qq.com/wiki/doc/api/tools/sp_coupon.php?chapter=12_1
                               ## ，不长于32位。
    notify_url*: string ## 接收微信支付异步通知回调地址，通知url必须为直接可访问的url，不能携带参数，
                        ## 不长于256位。
    trade_type*: TradeType ## 支付类型
    limit_pay*: Option[LimitPay] ## no_credit--指定不能使用信用卡支付
    receipt*: Option[string] ## Y，传入Y时，支付成功消息和支付详情页将出现开票入口。需要在微信支付商户平台
                             ## 或微信公众平台开通电子发票功能，传此字段才可生效，不长于8位。
    scene_info*: Option[string] ## 该字段常用于线下活动时的场景信息上报，支持上报实际门店信息，商户也可以
                                ## 按需求自己上报相关信息，不长于256位。该字段为JSON对象数据，对象格式为
                                ## {"store_info":{"id": "门店ID","name": "名称","area_code": "编码","address": "地址" }}

  PlaceOrderResponseResultSuccessBody* = ref object ## 下单成功响应内容
    trade_type*: TradeType ## 调用接口提交的交易类型，不能用付款码
    prepay_id*: string ## 微信生成的预支付会话标识，用于后续接口调用中使用，该值有效期为 2 小时

  PlaceOrderResponseReturnSuccessBody* = ref object ## 下单接口调用成功响应内容
    appid*: string ## 调用接口提交的应用ID
    mch_id*: string ## 调用接口提交的商户号
    device_info*: Option[string] ## 调用接口提交的终端设备号
    nonce_str*: string ## 微信返回的随机字符串
    sign*: string ## 微信返回的签名
    result_code*: ResultCode ## 业务结果
    err_code*: Option[PlaceOrderError] ## 错误代码
    err_code_des*: Option[string] ## 错误返回的信息描述
    success_body*: Option[PlaceOrderResponseResultSuccessBody] ## result code 为 SUCCESS 时返回的内容

  PlaceOrderResponseBody* = ref object of ResponseBody ## 下单后响应内容
    success_body*: Option[PlaceOrderResponseReturnSuccessBody] ## return code 为 SUCCESS 的时候返回的内容

  ResultResponseSuccessBody* = ref object ## 支付结果通知成功响应内容
    appid*: string ## 微信分配的小程序ID
    mch_id*: string ## 微信支付分配的商户号
    device_info*: Option[string] ## 微信支付分配的终端设备号
    nonce_str*: string ## 随机字符串，不长于32位
    sign*: string ## 签名
    sign_type*: Option[SignType] ## 签名类型，目前支持HMAC-SHA256和MD5，默认为MD5
    result_code*: ResultCode ## 业务结果
    err_code*: Option[PlaceOrderError] ## 错误返回的信息描述
    err_code_des*: Option[string] ## 错误返回的信息描述
    openid*: string ## 用户在商户appid下的唯一标识
    is_subscribe*: bool ## 用户是否关注公众账号
    trade_type*: TradeType ## 交易类型: JSAPI, NATIVE, APP
    bank_type*: BankType ## 银行类型
    total_fee*: int ## 订单总金额，单位为分
    settlement_total_fee*: Option[int] ## 应结订单金额=订单金额-非充值代金券金额，应结订单金额<=订单金额。
    fee_type*: Option[FeeType] ## 货币类型，符合ISO4217标准的三位字母代码，默认人民币：CNY
    cash_fee*: int ## 现金支付金额订单现金支付金额
    cash_fee_type*: Option[FeeType] ## 货币类型，符合ISO4217标准的三位字母代码，默认人民币：CNY
    coupon_fee*: Option[int] ## 代金券金额<=订单金额，订单金额-代金券金额=现金支付金额
    coupon_count*: Option[int] ## 代金券使用数量
    coupon_types*: Option[seq[(uint, CouponType)]] ## 代金券类型
    coupon_ids*: Option[seq[(uint, string)]] ## 代金券ID
    coupon_fees*: Option[seq[(uint, int)]] ## 单个代金券支付金额
    transaction_id*: string ## 微信支付订单号
    out_trade_no*: string ## 商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*@ ，且在同一个商户号下唯一。
    attach*: Option[string] ## 商家数据包，原样返回
    time_end*: DateTime ## 支付完成时间

  ResultResponseBody* = ref object of ResponseBody ## 支付结果通知响应内容
    success_body*: Option[ResultResponseSuccessBody] ## return code 为 SUCCESS 的时候返回的内容

  QueryOrderRequestBody* = ref object ## 查询订单请求内容
    appid*: string ## 应用 ID
    mch_id*: string  ## 商户号
    transaction_id*: string ## 微信的订单号，优先使用
    out_trade_no*: string ## 商户系统内部的订单号，当没提供transaction_id时需要传这个。
    nonce_str*: string ## 随即字符串，不长于32位。
    sign*: string ## 签名

  QueryOrderResponseResultSuccessBody* = ref object ## 查询订单成功响应内容
    device_info*: Option[string] ## 微信支付分配的终端设备号
    openid*: string ## 用户在商户appid下的唯一标识
    is_subscribe*: bool ## 用户是否关注公众账号
    trade_type*: TradeType ## 交易类型: JSAPI, NATIVE, APP
    trade_state*: TradeState ## 交易状态
    bank_type*: BankType ## 银行类型
    total_fee*: int ## 订单总金额，单位为分
    fee_type*: Option[FeeType] ## 货币类型，符合ISO4217标准的三位字母代码，默认人民币：CNY
    cash_fee*: int ## 现金支付金额订单现金支付金额
    cash_fee_type*: Option[FeeType] ## 货币类型，符合ISO4217标准的三位字母代码，默认人民币：CNY
    settlement_total_fee*: Option[int] ## 应结订单金额=订单金额-非充值代金券金额，应结订单金额<=订单金额。
    coupon_fee*: Option[int] ## 代金券金额<=订单金额，订单金额-代金券金额=现金支付金额
    coupon_count*: Option[int] ## 代金券使用数量
    coupon_types*: Option[seq[(uint, CouponType)]] ## 代金券类型
    coupon_ids*: Option[seq[(uint, string)]] ## 代金券ID
    coupon_fees*: Option[seq[(uint, int)]] ## 单个代金券支付金额
    transaction_id*: string ## 微信支付订单号
    out_trade_no*: string ## 商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*@ ，且在同一个商户号下唯一。
    attach*: Option[string] ## 商家数据包，原样返回
    time_end*: DateTime ## 支付完成时间
    trade_state_desc*: string ## 交易状态描述, 对当前查询订单状态的描述和下一步操作的指引

  QueryOrderResponseReturnSuccessBody* = ref object ## 查询订单接口调用成功响应内容
    appid*: string ## 微信分配的小程序ID
    mch_id*: string ## 微信支付分配的商户号
    nonce_str*: string ## 随机字符串，不长于32位
    sign*: string ## 签名
    result_code*: ResultCode ## 业务结果
    err_code*: Option[QueryOrderError] ## 错误返回的信息描述
    err_code_des*: Option[string] ## 错误返回的信息描述
    success_body*: Option[QueryOrderResponseResultSuccessBody]

  QueryOrderResponseBody* = ref object of ResponseBody
    success_body*: Option[QueryOrderResponseReturnSuccessBody]

  CloseOrderRequestBody* = ref object ## 关闭订单请求内容
    appid*: string ## 应用 ID
    mch_id*: string  ## 商户号
    out_trade_no*: string ## 商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*@ ，且在同一个商户号下唯一。
    nonce_str*: string ## 随即字符串，不长于32位。
    sign*: string ## 签名

  CloseOrderResponseReturnSuccessBody* = ref object
    appid*: string ## 微信分配的小程序ID
    mch_id*: string ## 微信支付分配的商户号
    nonce_str*: string ## 随机字符串，不长于32位
    sign*: string ## 签名
    result_code*: ResultCode ## 业务结果
    result_msg*: string ## 业务结果描述
    err_code*: Option[CloseOrderError] ## 错误返回的信息描述
    err_code_des*: Option[string] ## 错误返回的信息描述

  CloseOrderResponseBody* = ref object of ResponseBody
    success_body*: Option[CloseOrderResponseReturnSuccessBody]

proc stringToTradeType(str: string): Option[TradeType] =
  case str:
    of "JSAPI":
      result = some(TradeType.JSAPI)
    of "NATIVE":
      result = some(TradeType.NATIVE)
    of "APP":
      result = some(TradeType.APP)
    of "MWEB":
      result = some(TradeType.MWEB)
    of "MICROPAY":
      result = some(TradeType.MICROPAY)
    else:
      result = none(TradeType)

proc stringToResultCode(code: string): ResultCode =
  if code == "SUCCESS":
    result = ResultCode.SUCCESS
  else:
    result = ResultCode.FAIL

proc stringToPlaceOrderError(code: string): Option[PlaceOrderError] =
  case code:
    of "INVALID_REQUEST":
      result = some(PlaceOrderError.INVALID_REQUEST)
    of "NOAUTH":
      result = some(PlaceOrderError.NOAUTH)
    of "NOTENOUGH":
      result = some(PlaceOrderError.NOTENOUGH)
    of "ORDERPAID":
      result = some(PlaceOrderError.ORDERPAID)
    of "ORDERCLOSED":
      result = some(PlaceOrderError.ORDERCLOSED)
    of "SYSTEMERROR":
      result = some(PlaceOrderError.SYSTEMERROR)
    of "APPID_NOT_EXIST":
      result = some(PlaceOrderError.APPID_NOT_EXIST)
    of "MCHID_NOT_EXIST":
      result = some(PlaceOrderError.MCHID_NOT_EXIST)
    of "APPID_MCHID_NOT_MATCH":
      result = some(PlaceOrderError.APPID_MCHID_NOT_MATCH)
    of "LACK_PARAMS":
      result = some(PlaceOrderError.LACK_PARAMS)
    of "OUT_TRADE_NO_USED":
      result = some(PlaceOrderError.OUT_TRADE_NO_USED)
    of "SIGNERROR":
      result = some(PlaceOrderError.SIGNERROR)
    of "XML_FORMAT_ERROR":
      result = some(PlaceOrderError.XML_FORMAT_ERROR)
    of "REQUIRE_POST_METHOD":
      result = some(PlaceOrderError.REQUIRE_POST_METHOD)
    of "POST_DATE_EMPTY":
      result = some(PlaceOrderError.POST_DATE_EMPTY)
    of "NOT_UTF8":
      result = some(PlaceOrderError.NOT_UTF8)
    else:
      result = none(PlaceOrderError)

proc stringToQueryOrderError(err: string): Option[QueryOrderError] =
  case err:
    of "ORDERNOTEXIST":
      result = some(QueryOrderError.ORDERNOTEXIST)
    of "SYSTEMERROR":
      result = some(QueryOrderError.SYSTEMERROR)
    else:
      result = none(QueryOrderError)

proc stringToCloseOrderError(err: string): Option[CloseOrderError] =
  case err:
    of "ORDERPAID":
      result = some(CloseOrderError.ORDERPAID)
    of "SYSTEMERROR":
      result = some(CloseOrderError.SYSTEMERROR)
    of "ORDERCLOSED":
      result = some(CloseOrderError.ORDERCLOSED)
    of "SIGNERROR":
      result = some(CloseOrderError.SIGNERROR)
    of "REQUIRE_POST_METHOD":
      result = some(CloseOrderError.REQUIRE_POST_METHOD)
    of "XML_FORMAT_ERROR":
      result = some(CloseOrderError.XML_FORMAT_ERROR)
    else:
      result = none(CloseOrderError)

proc stringToBankType(bank: string): Option[BankType] =
  case bank:
    of "ICBC_DEBIT":
      result = some(BankType.ICBC_DEBIT)
    of "ICBC_CREDIT":
      result = some(BankType.ICBC_CREDIT)
    of "ABC_DEBIT":
      result = some(BankType.ABC_DEBIT)
    of "ABC_CREDIT":
      result = some(BankType.ABC_CREDIT)
    of "PSBC_CREDIT":
      result = some(BankType.PSBC_CREDIT)
    of "PSBC_DEBIT":
      result = some(BankType.PSBC_DEBIT)
    of "CCB_DEBIT":
      result = some(BankType.CCB_DEBIT)
    of "CCB_CREDIT":
      result = some(BankType.CCB_CREDIT)
    of "CMB_DEBIT":
      result = some(BankType.CMB_DEBIT)
    of "CMB_CREDIT":
      result = some(BankType.CMB_CREDIT)
    of "BOC_DEBIT":
      result = some(BankType.BOC_DEBIT)
    of "BOC_CREDIT":
      result = some(BankType.BOC_CREDIT)
    of "COMM_DEBIT":
      result = some(BankType.COMM_DEBIT)
    of "COMM_CREDIT":
      result = some(BankType.COMM_CREDIT)
    of "SPDB_DEBIT":
      result = some(BankType.SPDB_DEBIT)
    of "SPDB_CREDIT":
      result = some(BankType.SPDB_CREDIT)
    of "GDB_DEBIT":
      result = some(BankType.GDB_DEBIT)
    of "GDB_CREDIT":
      result = some(BankType.GDB_CREDIT)
    of "CMBC_DEBIT":
      result = some(BankType.CMBC_DEBIT)
    of "CMBC_CREDIT":
      result = some(BankType.CMBC_CREDIT)
    of "PAB_DEBIT":
      result = some(BankType.PAB_DEBIT)
    of "PAB_CREDIT":
      result = some(BankType.PAB_CREDIT)
    of "CEB_DEBIT":
      result = some(BankType.CEB_DEBIT)
    of "CEB_CREDIT":
      result = some(BankType.CEB_CREDIT)
    of "CIB_DEBIT":
      result = some(BankType.CIB_DEBIT)
    of "CIB_CREDIT":
      result = some(BankType.CIB_CREDIT)
    of "CITIC_DEBIT":
      result = some(BankType.CITIC_DEBIT)
    of "CITIC_CREDIT":
      result = some(BankType.CITIC_CREDIT)
    of "BOSH_DEBIT":
      result = some(BankType.BOSH_DEBIT)
    of "BOSH_CREDIT":
      result = some(BankType.BOSH_CREDIT)
    of "AHRCUB_CREDIT":
      result = some(BankType.AHRCUB_CREDIT)
    of "AHRCUB_DEBIT":
      result = some(BankType.AHRCUB_DEBIT)
    of "AIB_DEBIT":
      result = some(BankType.AIB_DEBIT)
    of "ASCB_DEBIT":
      result = some(BankType.ASCB_DEBIT)
    of "ATRB_DEBIT":
      result = some(BankType.ATRB_DEBIT)
    of "BCZ_CREDIT":
      result = some(BankType.BCZ_CREDIT)
    of "BCZ_DEBIT":
      result = some(BankType.BCZ_DEBIT)
    of "BDB_DEBIT":
      result = some(BankType.BDB_DEBIT)
    of "BEEB_CREDIT":
      result = some(BankType.BEEB_CREDIT)
    of "BEEB_DEBIT":
      result = some(BankType.BEEB_DEBIT)
    of "BGZB_DEBIT":
      result = some(BankType.BGZB_DEBIT)
    of "BHB_CREDIT":
      result = some(BankType.BHB_CREDIT)
    of "BHB_DEBIT":
      result = some(BankType.BHB_DEBIT)
    of "BJRCB_CREDIT":
      result = some(BankType.BJRCB_CREDIT)
    of "BJRCB_DEBIT":
      result = some(BankType.BJRCB_DEBIT)
    of "BNC_CREDIT":
      result = some(BankType.BNC_CREDIT)
    of "BNC_DEBIT":
      result = some(BankType.BNC_DEBIT)
    of "BOB_CREDIT":
      result = some(BankType.BOB_CREDIT)
    of "BOB_DEBIT":
      result = some(BankType.BOB_DEBIT)
    of "BOBBG_CREDIT":
      result = some(BankType.BOBBG_CREDIT)
    of "BOBBG_DEBIT":
      result = some(BankType.BOBBG_DEBIT)
    of "BOCD_DEBIT":
      result = some(BankType.BOCD_DEBIT)
    of "BOCDB_DEBIT":
      result = some(BankType.BOCDB_DEBIT)
    of "BOCFB_DEBIT":
      result = some(BankType.BOCFB_DEBIT)
    of "BOCTS_DEBIT":
      result = some(BankType.BOCTS_DEBIT)
    of "BOD_CREDIT":
      result = some(BankType.BOD_CREDIT)
    of "BOD_DEBIT":
      result = some(BankType.BOD_DEBIT)
    of "BOFS_DEBIT":
      result = some(BankType.BOFS_DEBIT)
    of "BOHN_DEBIT":
      result = some(BankType.BOHN_DEBIT)
    of "BOIMCB_CREDIT":
      result = some(BankType.BOIMCB_CREDIT)
    of "BOIMCB_DEBIT":
      result = some(BankType.BOIMCB_DEBIT)
    of "BOJN_DEBIT":
      result = some(BankType.BOJN_DEBIT)
    of "BOJX_DEBIT":
      result = some(BankType.BOJX_DEBIT)
    of "BOLB_DEBIT":
      result = some(BankType.BOLB_DEBIT)
    of "BOLFB_DEBIT":
      result = some(BankType.BOLFB_DEBIT)
    of "BONX_CREDIT":
      result = some(BankType.BONX_CREDIT)
    of "BONX_DEBIT":
      result = some(BankType.BONX_DEBIT)
    of "BOPDS_DEBIT":
      result = some(BankType.BOPDS_DEBIT)
    of "BOPJ_DEBIT":
      result = some(BankType.BOPJ_DEBIT)
    of "BOQHB_CREDIT":
      result = some(BankType.BOQHB_CREDIT)
    of "BOQHB_DEBIT":
      result = some(BankType.BOQHB_DEBIT)
    of "BOSXB_DEBIT":
      result = some(BankType.BOSXB_DEBIT)
    of "BOSZS_DEBIT":
      result = some(BankType.BOSZS_DEBIT)
    of "BOTSB_DEBIT":
      result = some(BankType.BOTSB_DEBIT)
    of "BOZ_CREDIT":
      result = some(BankType.BOZ_CREDIT)
    of "BOZ_DEBIT":
      result = some(BankType.BOZ_DEBIT)
    of "BSB_CREDIT":
      result = some(BankType.BSB_CREDIT)
    of "BSB_DEBIT":
      result = some(BankType.BSB_DEBIT)
    of "BYK_DEBIT":
      result = some(BankType.BYK_DEBIT)
    of "CBHB_DEBIT":
      result = some(BankType.CBHB_DEBIT)
    of "CCAB_CREDIT":
      result = some(BankType.CCAB_CREDIT)
    of "CCAB_DEBIT":
      result = some(BankType.CCAB_DEBIT)
    of "CDRCB_DEBIT":
      result = some(BankType.CDRCB_DEBIT)
    of "CITIB_CREDIT":
      result = some(BankType.CITIB_CREDIT)
    of "CITIB_DEBIT":
      result = some(BankType.CITIB_DEBIT)
    of "CJCCB_DEBIT":
      result = some(BankType.CJCCB_DEBIT)
    of "CQB_CREDIT":
      result = some(BankType.CQB_CREDIT)
    of "CQB_DEBIT":
      result = some(BankType.CQB_DEBIT)
    of "CQRCB_CREDIT":
      result = some(BankType.CQRCB_CREDIT)
    of "CQRCB_DEBIT":
      result = some(BankType.CQRCB_DEBIT)
    of "CQTGB_DEBIT":
      result = some(BankType.CQTGB_DEBIT)
    of "CRB_CREDIT":
      result = some(BankType.CRB_CREDIT)
    of "CRB_DEBIT":
      result = some(BankType.CRB_DEBIT)
    of "CSCB_CREDIT":
      result = some(BankType.CSCB_CREDIT)
    of "CSCB_DEBIT":
      result = some(BankType.CSCB_DEBIT)
    of "CSRCB_CREDIT":
      result = some(BankType.CSRCB_CREDIT)
    of "CSRCB_DEBIT":
      result = some(BankType.CSRCB_DEBIT)
    of "CSXB_DEBIT":
      result = some(BankType.CSXB_DEBIT)
    of "CYCB_CREDIT":
      result = some(BankType.CYCB_CREDIT)
    of "CYCB_DEBIT":
      result = some(BankType.CYCB_DEBIT)
    of "CZB_CREDIT":
      result = some(BankType.CZB_CREDIT)
    of "CZB_DEBIT":
      result = some(BankType.CZB_DEBIT)
    of "CZCB_CREDIT":
      result = some(BankType.CZCB_CREDIT)
    of "CZCB_DEBIT":
      result = some(BankType.CZCB_DEBIT)
    of "CZCCB_DEBIT":
      result = some(BankType.CZCCB_DEBIT)
    of "DANDONGB_CREDIT":
      result = some(BankType.DANDONGB_CREDIT)
    of "DANDONGB_DEBIT":
      result = some(BankType.DANDONGB_DEBIT)
    of "DBSB_DEBIT":
      result = some(BankType.DBSB_DEBIT)
    of "DCSFRB_DEBIT":
      result = some(BankType.DCSFRB_DEBIT)
    of "DHDYB_DEBIT":
      result = some(BankType.DHDYB_DEBIT)
    of "DHRB_DEBIT":
      result = some(BankType.DHRB_DEBIT)
    of "DLB_CREDIT":
      result = some(BankType.DLB_CREDIT)
    of "DLB_DEBIT":
      result = some(BankType.DLB_DEBIT)
    of "DLRCB_DEBIT":
      result = some(BankType.DLRCB_DEBIT)
    of "DRCB_CREDIT":
      result = some(BankType.DRCB_CREDIT)
    of "DRCB_DEBIT":
      result = some(BankType.DRCB_DEBIT)
    of "DSB_DEBIT":
      result = some(BankType.DSB_DEBIT)
    of "DTCCB_DEBIT":
      result = some(BankType.DTCCB_DEBIT)
    of "DYB_CREDIT":
      result = some(BankType.DYB_CREDIT)
    of "DYB_DEBIT":
      result = some(BankType.DYB_DEBIT)
    of "DYCCB_DEBIT":
      result = some(BankType.DYCCB_DEBIT)
    of "DYLSB_DEBIT":
      result = some(BankType.DYLSB_DEBIT)
    of "DZB_DEBIT":
      result = some(BankType.DZB_DEBIT)
    of "DZCCB_DEBIT":
      result = some(BankType.DZCCB_DEBIT)
    of "EDRB_DEBIT":
      result = some(BankType.EDRB_DEBIT)
    of "ESUNB_DEBIT":
      result = some(BankType.ESUNB_DEBIT)
    of "FBB_DEBIT":
      result = some(BankType.FBB_DEBIT)
    of "FDB_CREDIT":
      result = some(BankType.FDB_CREDIT)
    of "FDB_DEBIT":
      result = some(BankType.FDB_DEBIT)
    of "FJHXB_CREDIT":
      result = some(BankType.FJHXB_CREDIT)
    of "FJHXB_DEBIT":
      result = some(BankType.FJHXB_DEBIT)
    of "FJNX_CREDIT":
      result = some(BankType.FJNX_CREDIT)
    of "FJNX_DEBIT":
      result = some(BankType.FJNX_DEBIT)
    of "FUXINB_CREDIT":
      result = some(BankType.FUXINB_CREDIT)
    of "FUXINB_DEBIT":
      result = some(BankType.FUXINB_DEBIT)
    of "FXLZB_DEBIT":
      result = some(BankType.FXLZB_DEBIT)
    of "GADRB_DEBIT":
      result = some(BankType.GADRB_DEBIT)
    of "GDHX_DEBIT":
      result = some(BankType.GDHX_DEBIT)
    of "GDNYB_CREDIT":
      result = some(BankType.GDNYB_CREDIT)
    of "GDNYB_DEBIT":
      result = some(BankType.GDNYB_DEBIT)
    of "GDRCU_DEBIT":
      result = some(BankType.GDRCU_DEBIT)
    of "GLB_CREDIT":
      result = some(BankType.GLB_CREDIT)
    of "GLB_DEBIT":
      result = some(BankType.GLB_DEBIT)
    of "GLGMCB_DEBIT":
      result = some(BankType.GLGMCB_DEBIT)
    of "GRCB_CREDIT":
      result = some(BankType.GRCB_CREDIT)
    of "GRCB_DEBIT":
      result = some(BankType.GRCB_DEBIT)
    of "GSB_DEBIT":
      result = some(BankType.GSB_DEBIT)
    of "GSNX_DEBIT":
      result = some(BankType.GSNX_DEBIT)
    of "GSRB_DEBIT":
      result = some(BankType.GSRB_DEBIT)
    of "GXNX_CREDIT":
      result = some(BankType.GXNX_CREDIT)
    of "GXNX_DEBIT":
      result = some(BankType.GXNX_DEBIT)
    of "GYCB_CREDIT":
      result = some(BankType.GYCB_CREDIT)
    of "GYCB_DEBIT":
      result = some(BankType.GYCB_DEBIT)
    of "GZCB_CREDIT":
      result = some(BankType.GZCB_CREDIT)
    of "GZCB_DEBIT":
      result = some(BankType.GZCB_DEBIT)
    of "GZCCB_CREDIT":
      result = some(BankType.GZCCB_CREDIT)
    of "GZCCB_DEBIT":
      result = some(BankType.GZCCB_DEBIT)
    of "GZNX_DEBIT":
      result = some(BankType.GZNX_DEBIT)
    of "HAINNX_CREDIT":
      result = some(BankType.HAINNX_CREDIT)
    of "HAINNX_DEBIT":
      result = some(BankType.HAINNX_DEBIT)
    of "HANAB_DEBIT":
      result = some(BankType.HANAB_DEBIT)
    of "HBCB_CREDIT":
      result = some(BankType.HBCB_CREDIT)
    of "HBCB_DEBIT":
      result = some(BankType.HBCB_DEBIT)
    of "HBNX_CREDIT":
      result = some(BankType.HBNX_CREDIT)
    of "HBNX_DEBIT":
      result = some(BankType.HBNX_DEBIT)
    of "HDCB_DEBIT":
      result = some(BankType.HDCB_DEBIT)
    of "HEBNX_DEBIT":
      result = some(BankType.HEBNX_DEBIT)
    of "HFB_CREDIT":
      result = some(BankType.HFB_CREDIT)
    of "HFB_DEBIT":
      result = some(BankType.HFB_DEBIT)
    of "HKB_CREDIT":
      result = some(BankType.HKB_CREDIT)
    of "HKB_DEBIT":
      result = some(BankType.HKB_DEBIT)
    of "HKBEA_CREDIT":
      result = some(BankType.HKBEA_CREDIT)
    of "HKBEA_DEBIT":
      result = some(BankType.HKBEA_DEBIT)
    of "HKUB_DEBIT":
      result = some(BankType.HKUB_DEBIT)
    of "HLDCCB_DEBIT":
      result = some(BankType.HLDCCB_DEBIT)
    of "HLDYB_DEBIT":
      result = some(BankType.HLDYB_DEBIT)
    of "HLJRCUB_DEBIT":
      result = some(BankType.HLJRCUB_DEBIT)
    of "HMCCB_DEBIT":
      result = some(BankType.HMCCB_DEBIT)
    of "HNNX_DEBIT":
      result = some(BankType.HNNX_DEBIT)
    of "HRBB_CREDIT":
      result = some(BankType.HRBB_CREDIT)
    of "HRBB_DEBIT":
      result = some(BankType.HRBB_DEBIT)
    of "HRCB_DEBIT":
      result = some(BankType.HRCB_DEBIT)
    of "HRXJB_CREDIT":
      result = some(BankType.HRXJB_CREDIT)
    of "HRXJB_DEBIT":
      result = some(BankType.HRXJB_DEBIT)
    of "HSB_CREDIT":
      result = some(BankType.HSB_CREDIT)
    of "HSB_DEBIT":
      result = some(BankType.HSB_DEBIT)
    of "HSBC_DEBIT":
      result = some(BankType.HSBC_DEBIT)
    of "HSBCC_CREDIT":
      result = some(BankType.HSBCC_CREDIT)
    of "HSBCC_DEBIT":
      result = some(BankType.HSBCC_DEBIT)
    of "HSCB_DEBIT":
      result = some(BankType.HSCB_DEBIT)
    of "HUIHEB_DEBIT":
      result = some(BankType.HUIHEB_DEBIT)
    of "HUNNX_DEBIT":
      result = some(BankType.HUNNX_DEBIT)
    of "HUSRB_DEBIT":
      result = some(BankType.HUSRB_DEBIT)
    of "HXB_CREDIT":
      result = some(BankType.HXB_CREDIT)
    of "HXB_DEBIT":
      result = some(BankType.HXB_DEBIT)
    of "HZB_CREDIT":
      result = some(BankType.HZB_CREDIT)
    of "HZB_DEBIT":
      result = some(BankType.HZB_DEBIT)
    of "HZCCB_DEBIT":
      result = some(BankType.HZCCB_DEBIT)
    of "IBKB_DEBIT":
      result = some(BankType.IBKB_DEBIT)
    of "JCB_DEBIT":
      result = some(BankType.JCB_DEBIT)
    of "JCBK_CREDIT":
      result = some(BankType.JCBK_CREDIT)
    of "JDHDB_DEBIT":
      result = some(BankType.JDHDB_DEBIT)
    of "JDZCCB_DEBIT":
      result = some(BankType.JDZCCB_DEBIT)
    of "JHCCB_CREDIT":
      result = some(BankType.JHCCB_CREDIT)
    of "JHCCB_DEBIT":
      result = some(BankType.JHCCB_DEBIT)
    of "JJCCB_CREDIT":
      result = some(BankType.JJCCB_CREDIT)
    of "JJCCB_DEBIT":
      result = some(BankType.JJCCB_DEBIT)
    of "JLB_CREDIT":
      result = some(BankType.JLB_CREDIT)
    of "JLB_DEBIT":
      result = some(BankType.JLB_DEBIT)
    of "JLNX_DEBIT":
      result = some(BankType.JLNX_DEBIT)
    of "JNRCB_CREDIT":
      result = some(BankType.JNRCB_CREDIT)
    of "JNRCB_DEBIT":
      result = some(BankType.JNRCB_DEBIT)
    of "JRCB_CREDIT":
      result = some(BankType.JRCB_CREDIT)
    of "JRCB_DEBIT":
      result = some(BankType.JRCB_DEBIT)
    of "JSB_CREDIT":
      result = some(BankType.JSB_CREDIT)
    of "JSB_DEBIT":
      result = some(BankType.JSB_DEBIT)
    of "JSHB_CREDIT":
      result = some(BankType.JSHB_CREDIT)
    of "JSHB_DEBIT":
      result = some(BankType.JSHB_DEBIT)
    of "JSNX_CREDIT":
      result = some(BankType.JSNX_CREDIT)
    of "JSNX_DEBIT":
      result = some(BankType.JSNX_DEBIT)
    of "JUFENGB_DEBIT":
      result = some(BankType.JUFENGB_DEBIT)
    of "JXB_DEBIT":
      result = some(BankType.JXB_DEBIT)
    of "JXNXB_DEBIT":
      result = some(BankType.JXNXB_DEBIT)
    of "JZB_CREDIT":
      result = some(BankType.JZB_CREDIT)
    of "JZB_DEBIT":
      result = some(BankType.JZB_DEBIT)
    of "JZCB_CREDIT":
      result = some(BankType.JZCB_CREDIT)
    of "JZCB_DEBIT":
      result = some(BankType.JZCB_DEBIT)
    of "KCBEB_DEBIT":
      result = some(BankType.KCBEB_DEBIT)
    of "KLB_CREDIT":
      result = some(BankType.KLB_CREDIT)
    of "KLB_DEBIT":
      result = some(BankType.KLB_DEBIT)
    of "KRCB_DEBIT":
      result = some(BankType.KRCB_DEBIT)
    of "KSHB_DEBIT":
      result = some(BankType.KSHB_DEBIT)
    of "KUERLECB_DEBIT":
      result = some(BankType.KUERLECB_DEBIT)
    of "LCYRB_DEBIT":
      result = some(BankType.LCYRB_DEBIT)
    of "LICYRB_DEBIT":
      result = some(BankType.LICYRB_DEBIT)
    of "LJB_DEBIT":
      result = some(BankType.LJB_DEBIT)
    of "LLB_DEBIT":
      result = some(BankType.LLB_DEBIT)
    of "LLHZCB_DEBIT":
      result = some(BankType.LLHZCB_DEBIT)
    of "LNNX_DEBIT":
      result = some(BankType.LNNX_DEBIT)
    of "LPCB_DEBIT":
      result = some(BankType.LPCB_DEBIT)
    of "LPSBLVB_DEBIT":
      result = some(BankType.LPSBLVB_DEBIT)
    of "LSB_CREDIT":
      result = some(BankType.LSB_CREDIT)
    of "LSB_DEBIT":
      result = some(BankType.LSB_DEBIT)
    of "LSCCB_DEBIT":
      result = some(BankType.LSCCB_DEBIT)
    of "LUZB_DEBIT":
      result = some(BankType.LUZB_DEBIT)
    of "LWB_DEBIT":
      result = some(BankType.LWB_DEBIT)
    of "LYYHB_DEBIT":
      result = some(BankType.LYYHB_DEBIT)
    of "LZB_CREDIT":
      result = some(BankType.LZB_CREDIT)
    of "LZB_DEBIT":
      result = some(BankType.LZB_DEBIT)
    of "LZCCB_DEBIT":
      result = some(BankType.LZCCB_DEBIT)
    of "MHBRB_DEBIT":
      result = some(BankType.MHBRB_DEBIT)
    of "MINTAIB_CREDIT":
      result = some(BankType.MINTAIB_CREDIT)
    of "MINTAIB_DEBIT":
      result = some(BankType.MINTAIB_DEBIT)
    of "MPJDRB_DEBIT":
      result = some(BankType.MPJDRB_DEBIT)
    of "MYCCB_DEBIT":
      result = some(BankType.MYCCB_DEBIT)
    of "NBCB_CREDIT":
      result = some(BankType.NBCB_CREDIT)
    of "NBCB_DEBIT":
      result = some(BankType.NBCB_DEBIT)
    of "NCB_DEBIT":
      result = some(BankType.NCB_DEBIT)
    of "NCBCB_DEBIT":
      result = some(BankType.NCBCB_DEBIT)
    of "NCCB_DEBIT":
      result = some(BankType.NCCB_DEBIT)
    of "NJCB_CREDIT":
      result = some(BankType.NJCB_CREDIT)
    of "NJCB_DEBIT":
      result = some(BankType.NJCB_DEBIT)
    of "NJJDRB_DEBIT":
      result = some(BankType.NJJDRB_DEBIT)
    of "NJXLRB_DEBIT":
      result = some(BankType.NJXLRB_DEBIT)
    of "NMGNX_DEBIT":
      result = some(BankType.NMGNX_DEBIT)
    of "NNGMB_DEBIT":
      result = some(BankType.NNGMB_DEBIT)
    of "NUB_DEBIT":
      result = some(BankType.NUB_DEBIT)
    of "NYCCB_DEBIT":
      result = some(BankType.NYCCB_DEBIT)
    of "OCBCWHCB_DEBIT":
      result = some(BankType.OCBCWHCB_DEBIT)
    of "OHVB_DEBIT":
      result = some(BankType.OHVB_DEBIT)
    of "ORDOSB_CREDIT":
      result = some(BankType.ORDOSB_CREDIT)
    of "ORDOSB_DEBIT":
      result = some(BankType.ORDOSB_DEBIT)
    of "PBDLRB_DEBIT":
      result = some(BankType.PBDLRB_DEBIT)
    of "PJDWHFB_DEBIT":
      result = some(BankType.PJDWHFB_DEBIT)
    of "PJJYRB_DEBIT":
      result = some(BankType.PJJYRB_DEBIT)
    of "PZHCCB_DEBIT":
      result = some(BankType.PZHCCB_DEBIT)
    of "QDCCB_CREDIT":
      result = some(BankType.QDCCB_CREDIT)
    of "QDCCB_DEBIT":
      result = some(BankType.QDCCB_DEBIT)
    of "QHDB_DEBIT":
      result = some(BankType.QHDB_DEBIT)
    of "QHJDRB_DEBIT":
      result = some(BankType.QHJDRB_DEBIT)
    of "QHNX_DEBIT":
      result = some(BankType.QHNX_DEBIT)
    of "QJSYB_DEBIT":
      result = some(BankType.QJSYB_DEBIT)
    of "QLB_CREDIT":
      result = some(BankType.QLB_CREDIT)
    of "QLB_DEBIT":
      result = some(BankType.QLB_DEBIT)
    of "QLVB_DEBIT":
      result = some(BankType.QLVB_DEBIT)
    of "QSB_CREDIT":
      result = some(BankType.QSB_CREDIT)
    of "QSB_DEBIT":
      result = some(BankType.QSB_DEBIT)
    of "QZCCB_CREDIT":
      result = some(BankType.QZCCB_CREDIT)
    of "QZCCB_DEBIT":
      result = some(BankType.QZCCB_DEBIT)
    of "RHCB_DEBIT":
      result = some(BankType.RHCB_DEBIT)
    of "RQCZB_DEBIT":
      result = some(BankType.RQCZB_DEBIT)
    of "RXYHB_DEBIT":
      result = some(BankType.RXYHB_DEBIT)
    of "RZB_DEBIT":
      result = some(BankType.RZB_DEBIT)
    of "SCB_CREDIT":
      result = some(BankType.SCB_CREDIT)
    of "SCB_DEBIT":
      result = some(BankType.SCB_DEBIT)
    of "SCNX_DEBIT":
      result = some(BankType.SCNX_DEBIT)
    of "SDEB_CREDIT":
      result = some(BankType.SDEB_CREDIT)
    of "SDEB_DEBIT":
      result = some(BankType.SDEB_DEBIT)
    of "SDRCU_DEBIT":
      result = some(BankType.SDRCU_DEBIT)
    of "SHHJB_DEBIT":
      result = some(BankType.SHHJB_DEBIT)
    of "SHINHAN_DEBIT":
      result = some(BankType.SHINHAN_DEBIT)
    of "SHRB_DEBIT":
      result = some(BankType.SHRB_DEBIT)
    of "SJB_CREDIT":
      result = some(BankType.SJB_CREDIT)
    of "SJB_DEBIT":
      result = some(BankType.SJB_DEBIT)
    of "SNB_DEBIT":
      result = some(BankType.SNB_DEBIT)
    of "SNCCB_DEBIT":
      result = some(BankType.SNCCB_DEBIT)
    of "SPDYB_DEBIT":
      result = some(BankType.SPDYB_DEBIT)
    of "SRB_DEBIT":
      result = some(BankType.SRB_DEBIT)
    of "SRCB_CREDIT":
      result = some(BankType.SRCB_CREDIT)
    of "SRCB_DEBIT":
      result = some(BankType.SRCB_DEBIT)
    of "SUZB_CREDIT":
      result = some(BankType.SUZB_CREDIT)
    of "SUZB_DEBIT":
      result = some(BankType.SUZB_DEBIT)
    of "SXNX_DEBIT":
      result = some(BankType.SXNX_DEBIT)
    of "SXXH_DEBIT":
      result = some(BankType.SXXH_DEBIT)
    of "SZRCB_CREDIT":
      result = some(BankType.SZRCB_CREDIT)
    of "SZRCB_DEBIT":
      result = some(BankType.SZRCB_DEBIT)
    of "TACCB_CREDIT":
      result = some(BankType.TACCB_CREDIT)
    of "TACCB_DEBIT":
      result = some(BankType.TACCB_DEBIT)
    of "TCRCB_DEBIT":
      result = some(BankType.TCRCB_DEBIT)
    of "TJB_CREDIT":
      result = some(BankType.TJB_CREDIT)
    of "TJB_DEBIT":
      result = some(BankType.TJB_DEBIT)
    of "TJBHB_CREDIT":
      result = some(BankType.TJBHB_CREDIT)
    of "TJBHB_DEBIT":
      result = some(BankType.TJBHB_DEBIT)
    of "TJHMB_DEBIT":
      result = some(BankType.TJHMB_DEBIT)
    of "TJNHVB_DEBIT":
      result = some(BankType.TJNHVB_DEBIT)
    of "TLB_DEBIT":
      result = some(BankType.TLB_DEBIT)
    of "TLVB_DEBIT":
      result = some(BankType.TLVB_DEBIT)
    of "TMDYB_DEBIT":
      result = some(BankType.TMDYB_DEBIT)
    of "TRCB_CREDIT":
      result = some(BankType.TRCB_CREDIT)
    of "TRCB_DEBIT":
      result = some(BankType.TRCB_DEBIT)
    of "TZB_CREDIT":
      result = some(BankType.TZB_CREDIT)
    of "TZB_DEBIT":
      result = some(BankType.TZB_DEBIT)
    of "UOB_DEBIT":
      result = some(BankType.UOB_DEBIT)
    of "URB_DEBIT":
      result = some(BankType.URB_DEBIT)
    of "VBCB_DEBIT":
      result = some(BankType.VBCB_DEBIT)
    of "WACZB_DEBIT":
      result = some(BankType.WACZB_DEBIT)
    of "WB_DEBIT":
      result = some(BankType.WB_DEBIT)
    of "WEB_DEBIT":
      result = some(BankType.WEB_DEBIT)
    of "WEGOB_DEBIT":
      result = some(BankType.WEGOB_DEBIT)
    of "WFB_CREDIT":
      result = some(BankType.WFB_CREDIT)
    of "WFB_DEBIT":
      result = some(BankType.WFB_DEBIT)
    of "WHB_CREDIT":
      result = some(BankType.WHB_CREDIT)
    of "WHB_DEBIT":
      result = some(BankType.WHB_DEBIT)
    of "WHRC_CREDIT":
      result = some(BankType.WHRC_CREDIT)
    of "WHRC_DEBIT":
      result = some(BankType.WHRC_DEBIT)
    of "WHRYVB_DEBIT":
      result = some(BankType.WHRYVB_DEBIT)
    of "WJRCB_CREDIT":
      result = some(BankType.WJRCB_CREDIT)
    of "WJRCB_DEBIT":
      result = some(BankType.WJRCB_DEBIT)
    of "WLMQB_CREDIT":
      result = some(BankType.WLMQB_CREDIT)
    of "WLMQB_DEBIT":
      result = some(BankType.WLMQB_DEBIT)
    of "WRCB_CREDIT":
      result = some(BankType.WRCB_CREDIT)
    of "WRCB_DEBIT":
      result = some(BankType.WRCB_DEBIT)
    of "WUHAICB_DEBIT":
      result = some(BankType.WUHAICB_DEBIT)
    of "WZB_CREDIT":
      result = some(BankType.WZB_CREDIT)
    of "WZB_DEBIT":
      result = some(BankType.WZB_DEBIT)
    of "WZMSB_DEBIT":
      result = some(BankType.WZMSB_DEBIT)
    of "XAB_CREDIT":
      result = some(BankType.XAB_CREDIT)
    of "XAB_DEBIT":
      result = some(BankType.XAB_DEBIT)
    of "XCXPB_DEBIT":
      result = some(BankType.XCXPB_DEBIT)
    of "XHB_DEBIT":
      result = some(BankType.XHB_DEBIT)
    of "XHNMB_DEBIT":
      result = some(BankType.XHNMB_DEBIT)
    of "XIB_DEBIT":
      result = some(BankType.XIB_DEBIT)
    of "XINANB_DEBIT":
      result = some(BankType.XINANB_DEBIT)
    of "XJB_DEBIT":
      result = some(BankType.XJB_DEBIT)
    of "XJJDRB_DEBIT":
      result = some(BankType.XJJDRB_DEBIT)
    of "XJRCCB_DEBIT":
      result = some(BankType.XJRCCB_DEBIT)
    of "XMCCB_CREDIT":
      result = some(BankType.XMCCB_CREDIT)
    of "XMCCB_DEBIT":
      result = some(BankType.XMCCB_DEBIT)
    of "XRTB_DEBIT":
      result = some(BankType.XRTB_DEBIT)
    of "XTB_CREDIT":
      result = some(BankType.XTB_CREDIT)
    of "XTB_DEBIT":
      result = some(BankType.XTB_DEBIT)
    of "XWB_DEBIT":
      result = some(BankType.XWB_DEBIT)
    of "XXCB_DEBIT":
      result = some(BankType.XXCB_DEBIT)
    of "XXHZCB_DEBIT":
      result = some(BankType.XXHZCB_DEBIT)
    of "XXRB_DEBIT":
      result = some(BankType.XXRB_DEBIT)
    of "XYPQZYCB_DEBIT":
      result = some(BankType.XYPQZYCB_DEBIT)
    of "XZB_DEBIT":
      result = some(BankType.XZB_DEBIT)
    of "YACCB_DEBIT":
      result = some(BankType.YACCB_DEBIT)
    of "YBCCB_DEBIT":
      result = some(BankType.YBCCB_DEBIT)
    of "YKCB_DEBIT":
      result = some(BankType.YKCB_DEBIT)
    of "YLB_DEBIT":
      result = some(BankType.YLB_DEBIT)
    of "YNHTB_CREDIT":
      result = some(BankType.YNHTB_CREDIT)
    of "YNHTB_DEBIT":
      result = some(BankType.YNHTB_DEBIT)
    of "YNRCCB_CREDIT":
      result = some(BankType.YNRCCB_CREDIT)
    of "YNRCCB_DEBIT":
      result = some(BankType.YNRCCB_DEBIT)
    of "YQCCB_DEBIT":
      result = some(BankType.YQCCB_DEBIT)
    of "YQMYRB_DEBIT":
      result = some(BankType.YQMYRB_DEBIT)
    of "YRRCB_CREDIT":
      result = some(BankType.YRRCB_CREDIT)
    of "YRRCB_DEBIT":
      result = some(BankType.YRRCB_DEBIT)
    of "YTB_DEBIT":
      result = some(BankType.YTB_DEBIT)
    of "YYBSCB_DEBIT":
      result = some(BankType.YYBSCB_DEBIT)
    of "ZCRB_DEBIT":
      result = some(BankType.ZCRB_DEBIT)
    of "ZGB_DEBIT":
      result = some(BankType.ZGB_DEBIT)
    of "ZGCB_DEBIT":
      result = some(BankType.ZGCB_DEBIT)
    of "ZHCB_DEBIT":
      result = some(BankType.ZHCB_DEBIT)
    of "ZHQYTB_DEBIT":
      result = some(BankType.ZHQYTB_DEBIT)
    of "ZJB_DEBIT":
      result = some(BankType.ZJB_DEBIT)
    of "ZJLXRB_DEBIT":
      result = some(BankType.ZJLXRB_DEBIT)
    of "ZJRCUB_CREDIT":
      result = some(BankType.ZJRCUB_CREDIT)
    of "ZJRCUB_DEBIT":
      result = some(BankType.ZJRCUB_DEBIT)
    of "ZJTLCB_CREDIT":
      result = some(BankType.ZJTLCB_CREDIT)
    of "ZJTLCB_DEBIT":
      result = some(BankType.ZJTLCB_DEBIT)
    of "ZRCB_CREDIT":
      result = some(BankType.ZRCB_CREDIT)
    of "ZRCB_DEBIT":
      result = some(BankType.ZRCB_DEBIT)
    of "ZSXKCCB_DEBIT":
      result = some(BankType.ZSXKCCB_DEBIT)
    of "ZYB_CREDIT":
      result = some(BankType.ZYB_CREDIT)
    of "ZYB_DEBIT":
      result = some(BankType.ZYB_DEBIT)
    of "ZZB_CREDIT":
      result = some(BankType.ZZB_CREDIT)
    of "ZZB_DEBIT":
      result = some(BankType.ZZB_DEBIT)
    of "ZZCCB_DEBIT":
      result = some(BankType.ZZCCB_DEBIT)
    of "DINERSCLUD":
      result = some(BankType.DINERSCLUD)
    of "MASTERCARD":
      result = some(BankType.MASTERCARD)
    of "VISA":
      result = some(BankType.VISA)
    of "AMERICANEXPRESS":
      result = some(BankType.AMERICANEXPRESS)
    of "DISCOVER":
      result = some(BankType.DISCOVER)
    of "OTHERS":
      result = some(BankType.OTHERS)
    else:
      result = none(BankType)

proc stringToFeeType(str: string): Option[FeeType] =
  result = some(FeeType.CNY)

proc stringToCouponType(str: string): Option[CouponType] =
  case str:
    of "CASH":
      result = some(CouponType.CASH)
    of "NO_CASH":
      result = some(CouponType.NO_CASH)
    else:
      result = none(CouponType)

proc stringToTradeState(str: string): Option[TradeState] =
  case str:
    of "SUCCESS":
      result = some(TradeState.SUCCESS)
    of "REFUND":
      result = some(TradeState.REFUND)
    of "NOTPAY":
      result = some(TradeState.NOTPAY)
    of "CLOSED":
      result = some(TradeState.CLOSED)
    of "REVOKED":
      result = some(TradeState.REVOKED)
    of "USERPAYING":
      result = some(TradeState.USERPAYING)
    of "PAYERROR":
      result = some(TradeState.PAYERROR)
    else:
      result = none(TradeState)

macro addTag(t: untyped): untyped =
  result = nnkStmtList.newTree()
  let tag = genSym(nskVar)
  result.add newNimNode(nnkVarSection).add(
    newIdentDefs(tag, newEmptyNode(), newCall("newElement", toStrLit(t)))
  )
  result.add newCall("add", tag, newCall("newText", prefix(newDotExpr(ident("body"), t), "$")))
  result.add newCall("add", ident("result"), tag)

macro addOptionTag(t: untyped): untyped =
  result = nnkStmtList.newTree()
  let
    branch = nnkElifBranch.newTree()
    ifstmt = nnkIfStmt.newTree()
    tag = genSym(nskVar)
    code = nnkStmtList.newTree()
  code.add newNimNode(nnkVarSection).add(
    newIdentDefs(tag, newEmptyNode(), newCall("newElement", toStrLit(t)))
  )
  code.add newCall("add", tag, newCall("newText", prefix(newDotExpr(newDotExpr(ident("body"), t), ident("get")), "$")))
  code.add newCall("add", ident("result"), tag)
  branch.add newDotExpr(newDotExpr(ident("body"), t), ident("isSome"))
  branch.add code
  ifstmt.add branch
  result.add ifstmt

template fetchTag(x: XmlParser, val: Option[string]): untyped =
  x.next()
  while x.kind == xmlCharData or x.kind == xmlCData:
    if val.isSome:
      val = some(val.get("") & x.charData)
    else:
      val = some(x.charData)
    x.next()

const wxpayDateStyle* = "yyyyMMddHHmmss" ## 微信指定日期字符串格式

proc nonce*(l: uint = 32): string =
  ## 生成指定长度(不超过32)的随机字符串
  const alphabet = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
  var countdown = l
  while countdown > 0:
    let idx = rand(len(alphabet) - 1)
    result &= alphabet[idx]
    countdown -= 1

proc signMd5*(params: string, key: string): string =
  ## 将参数对`params`按 MD5 方式签名。
  ##
  ## 设所有发送或者接收到的数据为集合M，将集合M内非空参数值的参数按照参数名
  ## ASCII码从小到大排序(字典序)，使用URL键值对的格式(即key1=value1&key2=value2...)
  ## 拼接成字符串 `params`
  ##
  ## 特别注意以下重要规则：
  ##
  ## - 参数名ASCII码从小到大排序(字典序)。
  ## - 如果参数的值为空不参与签名。
  ## - 参数名区分大小写。
  ## - 验证调用返回或微信主动通知签名时，传送的sign参数不参与签名，将生成的签名与该sign值作校验。
  ## - 微信接口可能增加字段，验证签名时必须支持增加的扩展字段。
  ##
  ## 举例：
  ## 假设传送的参数如下：
  ##
  ## ..code-block::
  ##
  ##  appid： wxd930ea5d5a258f4f
  ##
  ##  mch_id： 10000100
  ##
  ##  device_info： 1000
  ##
  ##  body： test
  ##
  ##  nonce_str： ibuaiVcKdpRxkhJA
  ##
  ## 则 `params` 应该为：
  ##
  ## ..code-block::
  ##
  ##  appid=wxd930ea5d5a258f4f&body=test&device_info=1000&mch_id=10000100&nonce_str=ibuaiVcKdpRxkhJA
  ##
  ## `key` 为商户平台设置的密钥key, 设置路径：
  ##
  ##   微信商户平台(pay.weixin.qq.com)-->账户设置-->API安全-->密钥设置
  let tmp = params & "&key=" & key
  result = getMD5(tmp).toUpper

proc signHmacSha256*(params: string, key: string): string =
  ## 将参数对`params`按 HMAC-SHA256 方式签名。
  ##
  ## 设所有发送或者接收到的数据为集合M，将集合M内非空参数值的参数按照参数名
  ## ASCII码从小到大排序(字典序)，使用URL键值对的格式(即key1=value1&key2=value2...)
  ## 拼接成字符串 `params`
  ##
  ## 特别注意以下重要规则：
  ##
  ## - 参数名ASCII码从小到大排序(字典序)。
  ## - 如果参数的值为空不参与签名。
  ## - 参数名区分大小写。
  ## - 验证调用返回或微信主动通知签名时，传送的sign参数不参与签名，将生成的签名与该sign值作校验。
  ## - 微信接口可能增加字段，验证签名时必须支持增加的扩展字段。
  ##
  ## 举例：
  ## 假设传送的参数如下：
  ##
  ## ..code-block::
  ##
  ##  appid： wxd930ea5d5a258f4f
  ##
  ##  mch_id： 10000100
  ##
  ##  device_info： 1000
  ##
  ##  body： test
  ##
  ##  nonce_str： ibuaiVcKdpRxkhJA
  ##
  ## 则 `params` 应该为：
  ##
  ## ..code-block::
  ##
  ##  appid=wxd930ea5d5a258f4f&body=test&device_info=1000&mch_id=10000100&nonce_str=ibuaiVcKdpRxkhJA
  ##
  ## `key` 为商户平台设置的密钥key, 设置路径：
  ##
  ##   微信商户平台(pay.weixin.qq.com)-->账户设置-->API安全-->密钥设置
  let tmp = params & "&key=" & key
  result = toUpper(toHex(hmac_sha256(key, tmp)))

proc generateXml*(body: ResponseBody): XmlNode =
  ## 根据参数生成响应 xml
  result = newElement("xml")
  addTag(return_code)
  addOptionTag(return_msg)

const PlaceOrderUrl*: string = "https://api.mch.weixin.qq.com/pay/unifiedorder" ## 下单接口链接

proc signRequestBody*(body: PlaceOrderRequestBody, key: string): string =
  ## 对请求参数进行签名
  var
    params: seq[string] = @[]
  params.add("appid=" & body.appid)
  params.add("mch_id=" & body.mch_id)
  if body.device_info.isSome:
    params.add("device_info=" & body.device_info.get)
  params.add("nonce_str=" & body.nonce_str)
  if body.sign_type.isSome:
    params.add("sign_type=" & $body.sign_type.get(SignType.MD5))
  params.add("body=" & body.body)
  if body.detail.isSome:
    params.add("detail=" & body.detail.get)
  if body.attach.isSome:
    params.add("attach=" & body.attach.get)
  params.add("out_trade_no=" & body.out_trade_no)
  if body.fee_type.isSome:
    params.add("fee_type=" & $body.fee_type.get(FeeType.CNY))
  params.add("total_fee=" & $body.total_fee)
  params.add("spbill_create_ip=" & body.spbill_create_ip)
  if body.time_start.isSome:
    params.add("time_start=" & body.time_start.get.format(wxpayDateStyle))
  if body.time_expire.isSome:
    params.add("time_expire=" & body.time_expire.get.format(wxpayDateStyle))
  if body.goods_tag.isSome:
    params.add("goods_tag=" & body.goods_tag.get)
  params.add("notify_url=" & body.notify_url)
  params.add("trade_type=" & $body.trade_type)
  if body.limit_pay.isSome:
    params.add("limit_pay=" & $body.limit_pay.get)
  if body.receipt.isSome:
    params.add("receipt=" & body.receipt.get)
  if body.scene_info.isSome:
    params.add("scene_info=" & body.scene_info.get)
  let tmp = params.sorted.join("&")
  if body.sign_type.get(SignType.MD5) == SignType.HMAC_SHA256:
    result = signHmacSha256(tmp, key)
  else:
    result = signMd5(tmp, key)

proc generateXml*(body: PlaceOrderRequestBody): XmlNode =
  ## 根据参数生成下单请求 xml
  result = newElement("xml")
  addTag(appid)
  addTag(mch_id)
  addOptionTag(device_info)
  addTag(nonce_str)
  addTag(sign)
  addOptionTag(sign_type)
  addTag(body)
  addOptionTag(detail)
  addOptionTag(attach)
  addTag(out_trade_no)
  addOptionTag(fee_type)
  addTag(total_fee)
  addTag(spbill_create_ip)
  if body.time_start.isSome:
    var time_start = newElement("time_start")
    time_start.add newText(body.time_start.get.format(wxpayDateStyle))
    result.add(time_start)
  if body.time_expire.isSome:
    var time_expire = newElement("time_expire")
    time_expire.add newText(body.time_expire.get.format(wxpayDateStyle))
    result.add(time_expire)
  addOptionTag(goods_tag)
  addTag(notify_url)
  addTag(trade_type)
  addOptionTag(receipt)
  addOptionTag(scene_info)

proc parsePlaceOrderResponseBody*(body: string): PlaceOrderResponseBody =
  ## 从 XML 中解析出下单响应结果
  let strm = newStringStream(body)
  var
    x: XmlParser
    return_code: Option[string] = none[string]()
    return_msg: Option[string] = none[string]()
    appid: Option[string] = none[string]()
    mch_id: Option[string] = none[string]()
    device_info: Option[string] = none[string]()
    nonce_str: Option[string] = none[string]()
    sign: Option[string] = none[string]()
    result_code: Option[string] = none[string]()
    err_code: Option[string] = none[string]()
    err_code_des: Option[string] = none[string]()
    trade_type: Option[string] = none[string]()
    prepay_id: Option[string] = none[string]()
  open(x, strm, "string-stream")
  while true:
    x.next()
    case x.kind:
      of xmlElementStart:
        if x.elementName == "return_code":
          fetchTag(x, return_code)
        elif x.elementName == "return_msg":
          fetchTag(x, return_msg)
        elif x.elementName == "appid":
          fetchTag(x, appid)
        elif x.elementName == "mch_id":
          fetchTag(x, mch_id)
        elif x.elementName == "device_info":
          fetchTag(x, device_info)
        elif x.elementName == "nonce_str":
          fetchTag(x, nonce_str)
        elif x.elementName == "sign":
          fetchTag(x, sign)
        elif x.elementName == "result_code":
          fetchTag(x, result_code)
        elif x.elementName == "err_code":
          fetchTag(x, err_code)
        elif x.elementName == "err_code_des":
          fetchTag(x, err_code_des)
        elif x.elementName == "trade_type":
          fetchTag(x, trade_type)
        elif x.elementName == "prepay_id":
          fetchTag(x, prepay_id)
      of xmlEof:
        break
      else:
        continue
  x.close()
  result = PlaceOrderResponseBody()
  if return_code.isSome and return_code.get() == "SUCCESS":
    result.return_code = ReturnCode.SUCCESS
    if return_msg.isSome:
      result.return_msg = return_msg
    let success_body = PlaceOrderResponseReturnSuccessBody()
    if appid.isSome:
      success_body.appid = appid.get
    if mch_id.isSome:
      success_body.mch_id = mch_id.get
    success_body.device_info = device_info
    if nonce_str.isSome:
      success_body.nonce_str = nonce_str.get
    if sign.isSome:
      success_body.sign = sign.get
    if result_code.isSome:
      success_body.result_code = result_code.get.stringToResultCode
    else:
      success_body.result_code = ResultCode.FAIL
    if err_code.isSome:
      success_body.err_code = err_code.get.stringToPlaceOrderError
    else:
      success_body.err_code = none(PlaceOrderError)
    success_body.err_code_des = err_code_des
    result.success_body = some(success_body)
    let sub_success_body = PlaceOrderResponseResultSuccessBody()
    if success_body.result_code == ResultCode.SUCCESS:
      if trade_type.isSome:
        sub_success_body.trade_type = trade_type.get.stringToTradeType.get(TradeType.JSAPI)
      else:
        sub_success_body.trade_type = TradeType.JSAPI
      sub_success_body.prepay_id = prepay_id.get
      success_body.success_body = some(sub_success_body)
  else:
    result.return_code = ReturnCode.FAIL
    if return_msg.isSome:
      result.return_msg = return_msg

proc checkSign*(body: PlaceOrderResponseBody, key: string): Option[bool] =
  ## 检查签名
  ##
  ## 若结果为 none 说明返回结果中不含签名
  var params: seq[string] = @[]
  params.add("return_code=" & $body.return_code)
  if body.return_msg.isSome:
    params.add("return_msg=" & body.return_msg.get)
  if body.success_body.isSome:
    params.add("appid=" & body.success_body.get.appid)
    params.add("mch_id=" & body.success_body.get.mch_id)
    if body.success_body.get.device_info.isSome:
      params.add("device_info=" & body.success_body.get.device_info.get)
    params.add("nonce_str=" & body.success_body.get.nonce_str)
    params.add("result_code=" & $body.success_body.get.result_code)
    if body.success_body.get.err_code.isSome:
      params.add("err_code=" & $body.success_body.get.err_code.get)
    if body.success_body.get.err_code_des.isSome:
      params.add("err_code_des=" & body.success_body.get.err_code_des.get)
    if body.success_body.get.success_body.isSome:
      params.add("trade_type=" & $body.success_body.get.success_body.get.trade_type)
      params.add("prepay_id=" & $body.success_body.get.success_body.get.prepay_id)
    let tmp = params.sorted.join("&")
    result = some(signMd5(tmp, key) == body.success_body.get.sign)
  else:
    result = none(bool)


proc parseResultResponseBody*(body: string): ResultResponseBody =
  ## 从 XML 中解析出支付结果通知响应
  let strm = newStringStream(body)
  var
    x: XmlParser
    return_code: Option[string] = none[string]()
    return_msg: Option[string] = none[string]()
    appid: Option[string] = none[string]()
    mch_id: Option[string] = none[string]()
    device_info: Option[string] = none[string]()
    nonce_str: Option[string] = none[string]()
    sign: Option[string] = none[string]()
    sign_type: Option[string] = none[string]()
    result_code: Option[string] = none[string]()
    err_code: Option[string] = none[string]()
    err_code_des: Option[string] = none[string]()
    openid: Option[string] = none[string]()
    is_subscribe: Option[string] = none[string]()
    trade_type: Option[string] = none[string]()
    bank_type: Option[string] = none[string]()
    total_fee: Option[string] = none[string]()
    settlement_total_fee: Option[string] = none[string]()
    fee_type: Option[string] = none[string]()
    cash_fee: Option[string] = none[string]()
    cash_fee_type: Option[string] = none[string]()
    coupon_fee: Option[string] = none[string]()
    coupon_count: Option[string] = none[string]()
    transaction_id: Option[string] = none[string]()
    out_trade_no: Option[string] = none[string]()
    attach: Option[string] = none[string]()
    time_end: Option[string] = none[string]()
    coupon_types: Option[seq[(uint, string)]] = none[seq[(uint, string)]]()
    coupon_ids: Option[seq[(uint, string)]] = none[seq[(uint, string)]]()
    coupon_fees: Option[seq[(uint, string)]] = none[seq[(uint, string)]]()
  open(x, strm, "string-stream")
  while true:
    x.next()
    case x.kind:
      of xmlElementStart:
        if x.elementName == "return_code":
          fetchTag(x, return_code)
        elif x.elementName == "return_msg":
          fetchTag(x, return_msg)
        elif x.elementName == "appid":
          fetchTag(x, appid)
        elif x.elementName == "mch_id":
          fetchTag(x, mch_id)
        elif x.elementName == "device_info":
          fetchTag(x, device_info)
        elif x.elementName == "nonce_str":
          fetchTag(x, nonce_str)
        elif x.elementName == "sign":
          fetchTag(x, sign)
        elif x.elementName == "sign_type":
          fetchTag(x, sign_type)
        elif x.elementName == "result_code":
          fetchTag(x, result_code)
        elif x.elementName == "err_code":
          fetchTag(x, err_code)
        elif x.elementName == "err_code_des":
          fetchTag(x, err_code_des)
        elif x.elementName == "openid":
          fetchTag(x, openid)
        elif x.elementName == "is_subscribe":
          fetchTag(x, is_subscribe)
        elif x.elementName == "trade_type":
          fetchTag(x, trade_type)
        elif x.elementName == "bank_type":
          fetchTag(x, bank_type)
        elif x.elementName == "total_fee":
          fetchTag(x, total_fee)
        elif x.elementName == "settlement_total_fee":
          fetchTag(x, settlement_total_fee)
        elif x.elementName == "fee_type":
          fetchTag(x, fee_type)
        elif x.elementName == "cash_fee":
          fetchTag(x, cash_fee)
        elif x.elementName == "cash_fee_type":
          fetchTag(x, cash_fee_type)
        elif x.elementName == "coupon_fee":
          fetchTag(x, coupon_fee)
        elif x.elementName == "coupon_count":
          fetchTag(x, coupon_count)
        elif x.elementName == "transaction_id":
          fetchTag(x, transaction_id)
        elif x.elementName == "out_trade_no":
          fetchTag(x, out_trade_no)
        elif x.elementName == "attach":
          fetchTag(x, attach)
        elif x.elementName == "time_end":
          fetchTag(x, time_end)
        elif x.elementName.startsWith "coupon_type_":
          var
            idx = x.elementName.substr(len("coupon_type_")).parseUInt
            tmp = ""
          x.next()
          while x.kind == xmlCharData:
            tmp &= x.charData
            x.next()
          if coupon_types.isSome:
            coupon_types = some(concat(coupon_types.get(@[]), @[(idx, tmp)]))
          else:
            coupon_types = some(@[(idx, tmp)])
        elif x.elementName.startsWith "coupon_id_":
          var
            idx = x.elementName.substr(len("coupon_id_")).parseUInt
            tmp = ""
          x.next()
          while x.kind == xmlCharData:
            tmp &= x.charData
            x.next()
          if coupon_ids.isSome:
            coupon_ids = some(concat(coupon_ids.get(@[]), @[(idx, tmp)]))
          else:
            coupon_ids = some(@[(idx, tmp)])
        elif x.elementName.startsWith "coupon_fee_":
          var
            idx = x.elementName.substr(len("coupon_fee_")).parseUInt
            tmp = ""
          x.next()
          while x.kind == xmlCharData:
            tmp &= x.charData
            x.next()
          if coupon_fees.isSome:
            coupon_fees = some(concat(coupon_fees.get(@[]), @[(idx, tmp)]))
          else:
            coupon_fees = some(@[(idx, tmp)])
      of xmlEof:
        break
      else:
        continue
  x.close()
  result = ResultResponseBody()
  if return_code.isSome and return_code.get() == "SUCCESS":
    result.return_code = ReturnCode.SUCCESS
    if return_msg.isSome:
      result.return_msg = return_msg
    let success_body = ResultResponseSuccessBody(time_end: now())
    if appid.isSome:
      success_body.appid = appid.get
    if mch_id.isSome:
      success_body.mch_id = mch_id.get
    success_body.device_info = device_info
    if nonce_str.isSome:
      success_body.nonce_str = nonce_str.get
    if sign.isSome:
      success_body.sign = sign.get
    if result_code.isSome:
      success_body.result_code = result_code.get.stringToResultCode
    else:
      success_body.result_code = ResultCode.FAIL
    if err_code.isSome:
      success_body.err_code = err_code.get.stringToPlaceOrderError
    else:
      success_body.err_code = none(PlaceOrderError)
    success_body.err_code_des = err_code_des
    if openid.isSome:
      success_body.openid = openid.get
    if is_subscribe.isSome and is_subscribe.get("N") == "Y":
      success_body.is_subscribe = true
    else:
      success_body.is_subscribe = false
    if trade_type.isSome:
      success_body.trade_type = trade_type.get.stringToTradeType.get(TradeType.JSAPI)
    else:
      success_body.trade_type = TradeType.JSAPI
    if bank_type.isSome:
      success_body.bank_type = bank_type.get.stringToBankType.get(BankType.OTHERS)
    else:
      success_body.bank_type = BankType.OTHERS
    if total_fee.isSome:
      success_body.total_fee = total_fee.get("0").parseInt
    if settlement_total_fee.isSome:
      success_body.settlement_total_fee = some[int](settlement_total_fee.get("0").parseInt)
    if fee_type.isSome:
      success_body.fee_type = fee_type.get.stringToFeeType
    if cash_fee.isSome:
      success_body.cash_fee = cash_fee.get("0").parseInt
    if cash_fee_type.isSome:
      success_body.cash_fee_type = cash_fee_type.get.stringToFeeType
    if coupon_fee.isSome:
      success_body.coupon_fee = some[int](coupon_fee.get("0").parseInt)
    if coupon_count.isSome:
      success_body.coupon_count = some[int](coupon_count.get("0").parseInt)
    if transaction_id.isSome:
      success_body.transaction_id = transaction_id.get
    if out_trade_no.isSome:
      success_body.out_trade_no = out_trade_no.get
    success_body.attach = attach
    if time_end.isSome:
      success_body.time_end = time_end.get.parse(wxpayDateStyle, local())
    if coupon_types.isSome:
      success_body.coupon_types = some(coupon_types.get().mapIt((it[0], stringToCouponType(it[1]).get(CouponType.CASH))))
    success_body.coupon_ids = coupon_ids
    if coupon_fees.isSome:
      success_body.coupon_fees = some(coupon_fees.get().mapIt((it[0], parseInt(it[1]))))
    result.success_body = some(success_body)
  else:
    result.return_code = ReturnCode.FAIL
    if return_msg.isSome:
      result.return_msg = return_msg

proc checkSign*(body: ResultResponseBody, key: string): Option[bool] =
  ## 检查签名
  ##
  ## 若结果为 none 说明返回结果中不含签名
  var params: seq[string] = @[]
  params.add("return_code=" & $body.return_code)
  if body.return_msg.isSome:
    params.add("return_msg=" & body.return_msg.get)
  if body.success_body.isSome:
    params.add("appid=" & body.success_body.get.appid)
    params.add("mch_id=" & body.success_body.get.mch_id)
    if body.success_body.get.device_info.isSome:
      params.add("device_info=" & body.success_body.get.device_info.get)
    params.add("nonce_str=" & body.success_body.get.nonce_str)
    if body.success_body.get.sign_type.isSome:
      params.add("sign_type=" & $body.success_body.get.sign_type.get)
    params.add("result_code=" & $body.success_body.get.result_code)
    if body.success_body.get.err_code.isSome:
      params.add("err_code=" & $body.success_body.get.err_code.get)
    if body.success_body.get.err_code_des.isSome:
      params.add("err_code_des=" & body.success_body.get.err_code_des.get)
    params.add("openid=" & body.success_body.get.openid)
    params.add("is_subscribe=" & (if body.success_body.get.is_subscribe: "Y" else: "N"))
    params.add("trade_type=" & $body.success_body.get.trade_type)
    params.add("bank_type=" & $body.success_body.get.bank_type)
    params.add("total_fee=" & $body.success_body.get.total_fee)
    if body.success_body.get.settlement_total_fee.isSome:
      params.add("settlement_total_fee=" & $body.success_body.get.settlement_total_fee.get)
    if body.success_body.get.fee_type.isSome:
      params.add("fee_type=" & $body.success_body.get.fee_type.get)
    params.add("cash_fee=" & $body.success_body.get.cash_fee)
    if body.success_body.get.cash_fee_type.isSome:
      params.add("cash_fee_type=" & $body.success_body.get.cash_fee_type.get)
    if body.success_body.get.coupon_fee.isSome:
      params.add("coupon_fee=" & $body.success_body.get.coupon_fee.get)
    if body.success_body.get.coupon_count.isSome:
      params.add("coupon_count=" & $body.success_body.get.coupon_count.get)
    params.add("transaction_id=" & body.success_body.get.transaction_id)
    params.add("out_trade_no=" & body.success_body.get.out_trade_no)
    if body.success_body.get.attach.isSome:
      params.add("attach=" & $body.success_body.get.attach.get)
    params.add("time_end=" & body.success_body.get.time_end.format(wxpayDateStyle))
    if body.success_body.get.coupon_types.isSome:
      for (idx, ct) in body.success_body.get.coupon_types.get:
        params.add("coupon_type_" & $idx & "=" & $ct)
    if body.success_body.get.coupon_ids.isSome:
      for (idx, ci) in body.success_body.get.coupon_ids.get:
        params.add("coupon_type_" & $idx & "=" & ci)
    if body.success_body.get.coupon_fees.isSome:
      for (idx, cf) in body.success_body.get.coupon_fees.get:
        params.add("coupon_fee_" & $idx & "=" & $cf)
    let tmp = params.sorted.join("&")
    if body.success_body.get.sign_type.get(SignType.MD5) == SignType.HMAC_SHA256:
      result = some(signHmacSha256(tmp, key) == body.success_body.get.sign)
    else:
      result = some(signMd5(tmp, key) == body.success_body.get.sign)
  else:
    result = none(bool)

const QueryOrderUrl*: string = "https://api.mch.weixin.qq.com/pay/orderquery" ## 查询订单接口链接

proc signRequestBody*(body: QueryOrderRequestBody, key: string): string =
  ## 对请求参数进行签名
  var
    params: seq[string] = @[]
  params.add("appid=" & body.appid)
  params.add("mch_id=" & body.mch_id)
  if body.transaction_id.len > 0:
    params.add("transaction_id=" & body.transaction_id)
  else:
    params.add("out_trade_no=" & body.out_trade_no)
  params.add("nonce_str=" & body.nonce_str)
  let tmp = params.sorted.join("&")
  result = signMd5(tmp, key)

proc generateXml*(body: QueryOrderRequestBody): XmlNode =
  ## 根据参数生成查询订单请求 xml
  result = newElement("xml")

  addTag(appid)
  addTag(mch_id)

  if body.transaction_id.len > 0:
    addTag(transaction_id)
  else:
    addTag(out_trade_no)

  addTag(nonce_str)
  addTag(sign)

proc parseQueryOrderResponseBody*(body: string): QueryOrderResponseBody =
  ## 从 XML 中解析出查询订单响应结果
  let strm = newStringStream(body)
  var
    x: XmlParser
    return_code: Option[string] = none[string]()
    return_msg: Option[string] = none[string]()
    appid: Option[string] = none[string]()
    mch_id: Option[string] = none[string]()
    nonce_str: Option[string] = none[string]()
    sign: Option[string] = none[string]()
    result_code: Option[string] = none[string]()
    err_code: Option[string] = none[string]()
    err_code_des: Option[string] = none[string]()
    device_info: Option[string] = none[string]()
    openid: Option[string] = none[string]()
    is_subscribe: Option[string] = none[string]()
    trade_type: Option[string] = none[string]()
    trade_state: Option[string] = none[string]()
    bank_type: Option[string] = none[string]()
    total_fee: Option[string] = none[string]()
    fee_type: Option[string] = none[string]()
    cash_fee: Option[string] = none[string]()
    cash_fee_type: Option[string] = none[string]()
    settlement_total_fee: Option[string] = none[string]()
    coupon_fee: Option[string] = none[string]()
    coupon_count: Option[string] = none[string]()
    coupon_ids: seq[(uint, string)] = @[]
    coupon_types: seq[(uint, string)] = @[]
    coupon_fees: seq[(uint, string)] = @[]
    transaction_id: Option[string] = none[string]()
    out_trade_no: Option[string] = none[string]()
    attach: Option[string] = none[string]()
    time_end: Option[string] = none[string]()
    trade_state_desc: Option[string] = none[string]()
  open(x, strm, "string-stream")
  while true:
    x.next()
    case x.kind:
      of xmlElementStart:
        if x.elementName == "return_code":
          fetchTag(x, return_code)
        elif x.elementName == "return_msg":
          fetchTag(x, return_msg)
        elif x.elementName == "appid":
          fetchTag(x, appid)
        elif x.elementName == "mch_id":
          fetchTag(x, mch_id)
        elif x.elementName == "nonce_str":
          fetchTag(x, nonce_str)
        elif x.elementName == "sign":
          fetchTag(x, sign)
        elif x.elementName == "result_code":
          fetchTag(x, result_code)
        elif x.elementName == "err_code":
          fetchTag(x, err_code)
        elif x.elementName == "err_code_des":
          fetchTag(x, err_code_des)
        elif x.elementName == "device_info":
          fetchTag(x, device_info)
        elif x.elementName == "openid":
          fetchTag(x, openid)
        elif x.elementName == "is_subscribe":
          fetchTag(x, is_subscribe)
        elif x.elementName == "trade_type":
          fetchTag(x, trade_type)
        elif x.elementName == "trade_state":
          fetchTag(x, trade_state)
        elif x.elementName == "bank_type":
          fetchTag(x, bank_type)
        elif x.elementName == "total_fee":
          fetchTag(x, total_fee)
        elif x.elementName == "fee_type":
          fetchTag(x, fee_type)
        elif x.elementName == "cash_fee":
          fetchTag(x, cash_fee)
        elif x.elementName == "cash_fee_type":
          fetchTag(x, cash_fee_type)
        elif x.elementName == "settlement_total_fee":
          fetchTag(x, settlement_total_fee)
        elif x.elementName == "coupon_fee":
          fetchTag(x, coupon_fee)
        elif x.elementName == "coupon_count":
          fetchTag(x, coupon_count)
        elif x.elementName == "transaction_id":
          fetchTag(x, transaction_id)
        elif x.elementName == "out_trade_no":
          fetchTag(x, out_trade_no)
        elif x.elementName == "attach":
          fetchTag(x, attach)
        elif x.elementName == "time_end":
          fetchTag(x, time_end)
        elif x.elementName == "trade_state_desc":
          fetchTag(x, trade_state_desc)
        elif x.elementName.startsWith "coupon_type_":
          var
            idx = x.elementName.substr(len("coupon_type_")).parseUInt
            tmp = ""
          x.next()
          while x.kind == xmlCharData:
            tmp &= x.charData
            x.next()
          coupon_types.add((idx, tmp))
        elif x.elementName.startsWith "coupon_id_":
          var
            idx = x.elementName.substr(len("coupon_id_")).parseUInt
            tmp = ""
          x.next()
          while x.kind == xmlCharData:
            tmp &= x.charData
            x.next()
          coupon_ids.add((idx, tmp))
        elif x.elementName.startsWith "coupon_fee_":
          var
            idx = x.elementName.substr(len("coupon_fee_")).parseUInt
            tmp = ""
          x.next()
          while x.kind == xmlCharData:
            tmp &= x.charData
            x.next()
          coupon_fees.add((idx, tmp))
      of xmlEof:
        break
      else:
        continue
  x.close()
  result = QueryOrderResponseBody()
  if return_code.isSome and return_code.get() == "SUCCESS":
    result.return_code = ReturnCode.SUCCESS
    if return_msg.isSome:
      result.return_msg = return_msg
    let success_body = QueryOrderResponseReturnSuccessBody()
    if appid.isSome:
      success_body.appid = appid.get
    if mch_id.isSome:
      success_body.mch_id = mch_id.get
    if nonce_str.isSome:
      success_body.nonce_str = nonce_str.get
    if sign.isSome:
      success_body.sign = sign.get
    if result_code.isSome:
      success_body.result_code = result_code.get.stringToResultCode
    else:
      success_body.result_code = ResultCode.FAIL
    if err_code.isSome:
      success_body.err_code = err_code.get.stringToQueryOrderError
    else:
      success_body.err_code = none(QueryOrderError)
    success_body.err_code_des = err_code_des
    result.success_body = some(success_body)
    if success_body.result_code == ResultCode.SUCCESS:
      let sub_success_body = QueryOrderResponseResultSuccessBody(time_end: now())
      sub_success_body.device_info = device_info
      if openid.isSome:
        sub_success_body.openid = openid.get
      if is_subscribe.isSome and is_subscribe.get("N") == "Y":
        sub_success_body.is_subscribe = true
      else:
        sub_success_body.is_subscribe = false
      if trade_type.isSome:
        sub_success_body.trade_type = trade_type.get.stringToTradeType.get(TradeType.JSAPI)
      else:
        sub_success_body.trade_type = TradeType.JSAPI
      if trade_state.isSome:
        sub_success_body.trade_state = trade_state.get.stringToTradeState.get(TradeState.NOTPAY)
      else:
        sub_success_body.trade_state = TradeState.NOTPAY
      if bank_type.isSome:
        sub_success_body.bank_type = bank_type.get.stringToBankType.get(BankType.OTHERS)
      else:
        sub_success_body.bank_type = BankType.OTHERS
      if total_fee.isSome:
        sub_success_body.total_fee = total_fee.get("0").parseInt
      if fee_type.isSome:
        sub_success_body.fee_type = fee_type.get.stringToFeeType
      if cash_fee.isSome:
        sub_success_body.cash_fee = cash_fee.get("0").parseInt
      if cash_fee_type.isSome:
        sub_success_body.cash_fee_type = cash_fee_type.get.stringToFeeType
      if settlement_total_fee.isSome:
        sub_success_body.settlement_total_fee = some[int](settlement_total_fee.get("0").parseInt)
      if coupon_fee.isSome:
        sub_success_body.coupon_fee = some[int](coupon_fee.get("0").parseInt)
      if coupon_count.isSome:
        sub_success_body.coupon_count = some[int](coupon_count.get("0").parseInt)
      if transaction_id.isSome:
        sub_success_body.transaction_id = transaction_id.get
      if out_trade_no.isSome:
        sub_success_body.out_trade_no = out_trade_no.get
      sub_success_body.attach = attach
      if time_end.isSome:
        sub_success_body.time_end = time_end.get.parse(wxpayDateStyle, local())
      if trade_state_desc.isSome:
        sub_success_body.trade_state_desc = trade_state_desc.get
      if coupon_types.len > 0:
        sub_success_body.coupon_types = some(coupon_types.mapIt((it[0], stringToCouponType(it[1]).get(CouponType.CASH))))
      if coupon_ids.len > 0:
        sub_success_body.coupon_ids = some(coupon_ids)
      if coupon_fees.len > 0:
        sub_success_body.coupon_fees = some(coupon_fees.mapIt((it[0], parseInt(it[1]))))
      success_body.success_body = some(sub_success_body)
  else:
    result.return_code = ReturnCode.FAIL
    if return_msg.isSome:
      result.return_msg = return_msg

proc checkSign*(body: QueryOrderResponseBody, key: string): Option[bool] =
  ## 检查签名
  ##
  ## 若结果为 none 说明返回结果中不含签名
  var params: seq[string] = @[]
  params.add("return_code=" & $body.return_code)
  if body.return_msg.isSome:
    params.add("return_msg=" & body.return_msg.get)
  if body.success_body.isSome:
    params.add("appid=" & body.success_body.get.appid)
    params.add("mch_id=" & body.success_body.get.mch_id)
    params.add("nonce_str=" & body.success_body.get.nonce_str)
    params.add("result_code=" & $body.success_body.get.result_code)
    if body.success_body.get.err_code.isSome:
      params.add("err_code=" & $body.success_body.get.err_code.get)
    if body.success_body.get.err_code_des.isSome:
      params.add("err_code_des=" & body.success_body.get.err_code_des.get)
    if body.success_body.get.success_body.isSome:
      if body.success_body.get.success_body.get.device_info.isSome:
        params.add("device_info=" & body.success_body.get.success_body.get.device_info.get)
      params.add("openid=" & body.success_body.get.success_body.get.openid)
      params.add("is_subscribe=" & (if body.success_body.get.success_body.get.is_subscribe: "Y" else: "N"))
      params.add("trade_type=" & $body.success_body.get.success_body.get.trade_type)
      params.add("bank_type=" & $body.success_body.get.success_body.get.bank_type)
      params.add("total_fee=" & $body.success_body.get.success_body.get.total_fee)
      if body.success_body.get.success_body.get.settlement_total_fee.isSome:
        params.add("settlement_total_fee=" & $body.success_body.get.success_body.get.settlement_total_fee.get)
      if body.success_body.get.success_body.get.fee_type.isSome:
        params.add("fee_type=" & $body.success_body.get.success_body.get.fee_type.get)
      params.add("cash_fee=" & $body.success_body.get.success_body.get.cash_fee)
      if body.success_body.get.success_body.get.cash_fee_type.isSome:
        params.add("cash_fee_type=" & $body.success_body.get.success_body.get.cash_fee_type.get)
      params.add("coupon_fee=" & $body.success_body.get.success_body.get.coupon_fee)
      params.add("coupon_count=" & $body.success_body.get.success_body.get.coupon_count)
      params.add("transaction_id=" & body.success_body.get.success_body.get.transaction_id)
      params.add("out_trade_no=" & body.success_body.get.success_body.get.out_trade_no)
      if body.success_body.get.success_body.get.attach.isSome:
        params.add("attach=" & $body.success_body.get.success_body.get.attach.get)
      params.add("time_end=" & body.success_body.get.success_body.get.time_end.format(wxpayDateStyle))
      params.add("trade_state_desc=" & body.success_body.get.success_body.get.trade_state_desc)
      if body.success_body.get.success_body.get.coupon_types.isSome:
        for (idx, ct) in body.success_body.get.success_body.get.coupon_types.get:
          params.add("coupon_type_" & $idx & "=" & $ct)
      if body.success_body.get.success_body.get.coupon_ids.isSome:
        for (idx, ci) in body.success_body.get.success_body.get.coupon_ids.get:
          params.add("coupon_type_" & $idx & "=" & ci)
      if body.success_body.get.success_body.get.coupon_fees.isSome:
        for (idx, cf) in body.success_body.get.success_body.get.coupon_fees.get:
          params.add("coupon_fee_" & $idx & "=" & $cf)
      let tmp = params.sorted.join("&")
      result = some(signMd5(tmp, key) == body.success_body.get.sign)
    else:
      let tmp = params.sorted.join("&")
      result = some(signMd5(tmp, key) == body.success_body.get.sign)
  else:
    result = none(bool)


const CloseOrderUrl*: string = "https://api.mch.weixin.qq.com/pay/closeorder" ## 关闭订单接口链接

proc signRequestBody*(body: CloseOrderRequestBody, key: string): string =
  ## 对请求参数进行签名
  var
    params: seq[string] = @[]
  params.add("appid=" & body.appid)
  params.add("mch_id=" & body.mch_id)
  params.add("out_trade_no=" & body.out_trade_no)
  params.add("nonce_str=" & body.nonce_str)
  let tmp = params.sorted.join("&")
  result = signMd5(tmp, key)

proc generateXml*(body: CloseOrderRequestBody): XmlNode =
  ## 根据参数生成关闭订单请求 xml
  result = newElement("xml")
  addTag(appid)
  addTag(mch_id)
  addTag(out_trade_no)
  addTag(nonce_str)
  addTag(sign)

proc parseCloseOrderResponseBody*(body: string): CloseOrderResponseBody =
  ## 从 XML 中解析出关闭订单响应结果
  let strm = newStringStream(body)
  var
    x: XmlParser
    return_code: Option[string] = none[string]()
    return_msg: Option[string] = none[string]()
    appid: Option[string] = none[string]()
    mch_id: Option[string] = none[string]()
    nonce_str: Option[string] = none[string]()
    sign: Option[string] = none[string]()
    result_code: Option[string] = none[string]()
    result_msg: Option[string] = none[string]()
    err_code: Option[string] = none[string]()
    err_code_des: Option[string] = none[string]()
  open(x, strm, "string-stream")
  while true:
    x.next()
    case x.kind:
      of xmlElementStart:
        if x.elementName == "return_code":
          fetchTag(x, return_code)
        elif x.elementName == "return_msg":
          fetchTag(x, return_msg)
        elif x.elementName == "appid":
          fetchTag(x, appid)
        elif x.elementName == "mch_id":
          fetchTag(x, mch_id)
        elif x.elementName == "nonce_str":
          fetchTag(x, nonce_str)
        elif x.elementName == "sign":
          fetchTag(x, sign)
        elif x.elementName == "result_code":
          fetchTag(x, result_code)
        elif x.elementName == "result_msg":
          fetchTag(x, result_msg)
        elif x.elementName == "err_code":
          fetchTag(x, err_code)
        elif x.elementName == "err_code_des":
          fetchTag(x, err_code_des)
      of xmlEof:
        break
      else:
        continue
  x.close()
  result = CloseOrderResponseBody()
  if return_code.isSome and return_code.get() == "SUCCESS":
    result.return_code = ReturnCode.SUCCESS
    if return_msg.isSome:
      result.return_msg = return_msg
    let success_body = CloseOrderResponseReturnSuccessBody()
    if appid.isSome:
      success_body.appid = appid.get
    if mch_id.isSome:
      success_body.mch_id = mch_id.get
    if nonce_str.isSome:
      success_body.nonce_str = nonce_str.get
    if sign.isSome:
      success_body.sign = sign.get
    if result_code.isSome:
      success_body.result_code = result_code.get.stringToResultCode
    else:
      success_body.result_code = ResultCode.FAIL
    if result_msg.isSome:
      success_body.result_msg = result_msg.get
    if err_code.isSome:
      success_body.err_code = err_code.get.stringToCloseOrderError
    else:
      success_body.err_code = none(CloseOrderError)
    success_body.err_code_des = err_code_des
    result.success_body = some(success_body)
  else:
    result.return_code = ReturnCode.FAIL
    if return_msg.isSome:
      result.return_msg = return_msg

proc checkSign*(body: CloseOrderResponseBody, key: string): Option[bool] =
  ## 检查签名
  ##
  ## 若结果为 none 说明返回结果中不含签名
  var params: seq[string] = @[]
  params.add("return_code=" & $body.return_code)
  if body.return_msg.isSome:
    params.add("return_msg=" & body.return_msg.get)
  if body.success_body.isSome:
    params.add("appid=" & body.success_body.get.appid)
    params.add("mch_id=" & body.success_body.get.mch_id)
    params.add("nonce_str=" & body.success_body.get.nonce_str)
    params.add("result_code=" & $body.success_body.get.result_code)
    if body.success_body.get.err_code.isSome:
      params.add("err_code=" & $body.success_body.get.err_code.get)
    if body.success_body.get.err_code_des.isSome:
      params.add("err_code_des=" & body.success_body.get.err_code_des.get)
    let tmp = params.sorted.join("&")
    result = some(signMd5(tmp, key) == body.success_body.get.sign)
  else:
    result = none(bool)

