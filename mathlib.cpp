//
// Math Functions
//
// Copyright 2005-2008 Matt T. Yourst <yourst@yourst.com>
// Derived from various sources (glibc, etc)
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#include <globals.h>

namespace math {

#define HIGH_HALF 1
#define  LOW_HALF 0

  typedef int int4;

  typedef union {
    int4 i[2];
    double x;
  } mynumber;
  
#define ABS(x)   (((x)>0)?(x):-(x))
#define max(x,y)  (((y)>(x))?(y):(x))
#define min(x,y)  (((y)<(x))?(y):(x))

#undef NAN
  static const mynumber NAN = {{0x00000000, 0x7ff80000 }};/*  NaN                     */
  static const mynumber  s1 = {{0x55555555, 0xBFC55555 }};/* -0.16666666666666666     */
  static const mynumber  s2 = {{0x11110ECE, 0x3F811111 }};/*  0.0083333333333323288   */
  static const mynumber  s3 = {{0x19DB08B8, 0xBF2A01A0 }};/* -0.00019841269834414642  */
  static const mynumber  s4 = {{0x7B9A7ED9, 0x3EC71DE2 }};/*  2.755729806860771e-06   */
  static const mynumber  s5 = {{0xC2FCDF59, 0xBE5ADDFF }};/* -2.5022014848318398e-08  */
  static const mynumber  aa = {{0x00000000, 0xBFC55580 }};/* -0.1666717529296875      */
  static const mynumber  bb = {{0x55556E24, 0x3ED55555 }};/*  5.0862630208387126e-06  */
  static const mynumber big = {{0x00000000, 0x42c80000 }};/*  52776558133248          */
  static const mynumber hp0 = {{0x54442D18, 0x3FF921FB }};/*  1.5707963267948966      */
  static const mynumber hp1 = {{0x33145C07, 0x3C91A626 }};/*  6.123233995736766e-17   */
  static const mynumber mp1 = {{0x58000000, 0x3FF921FB }};/*  1.5707963407039642      */
  static const mynumber mp2 = {{0x3C000000, 0xBE4DDE97 }};/* -1.3909067564377153e-08  */
  static const mynumber mp3 = {{0x99D747F2, 0xBC8CB3B3 }};/* -4.9789962505147994e-17  */
  static const mynumber pp3 = {{0x98000000, 0xBC8CB3B3 }};/* -4.9789962314799099e-17  */
  static const mynumber pp4 = {{0x23e32ed7, 0xbacd747f }};/* -1.9034889620193266e-25  */
  static const mynumber hpinv = {{0x6DC9C883, 0x3FE45F30 }};/*  0.63661977236758138     */
  static const mynumber toint = {{0x00000000, 0x43380000 }};/*  6755399441055744        */

static const union { int4 i[880]; double x[440]; } sincos = { {
  0x00000000, 0x00000000,
  0x00000000, 0x00000000,
  0x00000000, 0x3FF00000,
  0x00000000, 0x00000000,
  0xAAAEEEEF, 0x3F7FFFEA,
  0xEC67B77C, 0xBC1E45E2,
  0x00155552, 0x3FEFFFC0,
  0xA0196DAE, 0x3C8F4A01,
  0xAAEEEED5, 0x3F8FFFAA,
  0x9A9F0777, 0xBC02AB63,
  0x0155549F, 0x3FEFFF00,
  0xA03A5EF3, 0x3C828A28,
  0x01033255, 0x3F97FF70,
  0x51527336, 0x3BFEFE2B,
  0x06BFF7E6, 0x3FEFFDC0,
  0xE86977BD, 0x3C8AE6DA,
  0xAEEEE86F, 0x3F9FFEAA,
  0xFB224AE2, 0xBC3CD406,
  0x155527D3, 0x3FEFFC00,
  0x92D89B5B, 0xBC83B544,
  0xB12D45D5, 0x3FA3FEB2,
  0x203D1C11, 0x3C34EC54,
  0x3414A7BA, 0x3FEFF9C0,
  0xBE6C59BF, 0x3C6991F4,
  0x1032FBA9, 0x3FA7FDC0,
  0xF46E997A, 0xBC4599BD,
  0x6BFDF99F, 0x3FEFF700,
  0x60648D5F, 0xBC78B3B5,
  0x78586DAC, 0x3FABFC6D,
  0x03DBF236, 0x3C18E4FD,
  0xC8103A31, 0x3FEFF3C0,
  0xBDDC0E66, 0x3C74856D,
  0xEEED4EDB, 0x3FAFFAAA,
  0x32684B69, 0xBC42D16D,
  0x5549F4D3, 0x3FEFF001,
  0x7B99426F, 0x3C832838,
  0x3D808BEF, 0x3FB1FC34,
  0xE6F3BE4F, 0xBC5F3D32,
  0x22A8EF9F, 0x3FEFEBC2,
  0x34F54C77, 0x3C579349,
  0x12D1755B, 0x3FB3FACB,
  0x5299468C, 0xBC592191,
  0x4129EF6F, 0x3FEFE703,
  0x37C96F97, 0xBC6CBF43,
  0xFD10B737, 0x3FB5F911,
  0x02BE9102, 0xBC50184F,
  0xC3C873EB, 0x3FEFE1C4,
  0x057C4A02, 0xBC35A9C9,
  0x032550E4, 0x3FB7F701,
  0x1800501A, 0x3C3AFC2D,
  0xBF7E6B9B, 0x3FEFDC06,
  0xB535F8DB, 0x3C831902,
  0x2D55D1F9, 0x3FB9F490,
  0x7EAC1DC1, 0x3C52696D,
  0x4B43E000, 0x3FEFD5C9,
  0xCB4F92F9, 0xBC62E768,
  0x8568391D, 0x3FBBF1B7,
  0x1DEA4CC8, 0x3C5E9184,
  0x800E99B1, 0x3FEFCF0C,
  0x86D186AC, 0x3C6EA3D7,
  0x16C1CCE6, 0x3FBDEE6F,
  0x2FB71673, 0xBC450F8E,
  0x78D1BC88, 0x3FEFC7D0,
  0x447DB685, 0x3C8075D2,
  0xEE86EE36, 0x3FBFEAAE,
  0xBCC6F03B, 0xBC4AFCB2,
  0x527D5BD3, 0x3FEFC015,
  0x5094EFB8, 0x3C8B68F3,
  0x8DDD71D1, 0x3FC0F337,
  0x724F0F9E, 0x3C6D8468,
  0x2BFE0695, 0x3FEFB7DB,
  0xF4F65AB1, 0x3C821DAD,
  0xD7AFCEAF, 0x3FC1F0D3,
  0x099769A5, 0xBC66EF95,
  0x263C4BD3, 0x3FEFAF22,
  0x133A2769, 0xBC552ACE,
  0x5E4AB88F, 0x3FC2EE28,
  0x05DEE058, 0xBC6E4D0F,
  0x641C36F2, 0x3FEFA5EA,
  0xED17CC7C, 0x3C404DA6,
  0x2C5D66CB, 0x3FC3EB31,
  0x6B66CB91, 0x3C647D66,
  0x0A7CC428, 0x3FEF9C34,
  0x063B7462, 0x3C8C5B6B,
  0x4DC5F27B, 0x3FC4E7EA,
  0x2AC072FC, 0x3C5949DB,
  0x40374D01, 0x3FEF91FF,
  0x4D3A9E4C, 0xBC67D03F,
  0xCFA126F3, 0x3FC5E44F,
  0x063F89B6, 0xBC66F443,
  0x2E1EECF6, 0x3FEF874C,
  0xE1332B16, 0xBC8C6514,
  0xC05A4D4C, 0x3FC6E05D,
  0x8B81C940, 0xBBD32C5C,
  0xFEFFDE24, 0x3FEF7C1A,
  0xC47540B1, 0xBC78F55B,
  0x2FBAF2B5, 0x3FC7DC10,
  0xE23C97C3, 0x3C45AB50,
  0xDF9ECE1C, 0x3FEF706B,
  0x0C36DCB4, 0xBC8698C8,
  0x2EFAA944, 0x3FC8D763,
  0x62CBB953, 0xBC620FA2,
  0xFEB82ACD, 0x3FEF643E,
  0xC1FE28AC, 0x3C76B00A,
  0xD0CEC312, 0x3FC9D252,
  0x80B1137D, 0x3C59C43D,
  0x8CFF6797, 0x3FEF5794,
  0x3E03B1D5, 0x3C6E3A0D,
  0x297A0765, 0x3FCACCDB,
  0x57D6CDEB, 0xBC59883B,
  0xBD1E3A79, 0x3FEF4A6C,
  0xEDAEBB57, 0x3C813DF0,
  0x4EDC6199, 0x3FCBC6F8,
  0x6A7B0CAB, 0x3C69C1A5,
  0xC3B3D16E, 0x3FEF3CC7,
  0xD28A3494, 0xBC621A3A,
  0x588289A3, 0x3FCCC0A6,
  0x9BC87C6B, 0xBC6868D0,
  0xD753FFED, 0x3FEF2EA5,
  0x5F56D583, 0x3C8CC421,
  0x5FB5A5D0, 0x3FCDB9E1,
  0xD6CC6FC2, 0xBC632E20,
  0x3086649F, 0x3FEF2007,
  0x16C1984B, 0x3C7B9404,
  0x7F8AE5A3, 0x3FCEB2A5,
  0xAF572CEB, 0xBC60BE06,
  0x09C5873B, 0x3FEF10EC,
  0x762C1283, 0x3C8D9072,
  0xD4F31577, 0x3FCFAAEE,
  0x508E32B8, 0xBC615D88,
  0x9F7DEEA1, 0x3FEF0154,
  0x99E5CAFD, 0x3C8D3C1E,
  0xBF65155C, 0x3FD0515C,
  0x9DFD8EC8, 0xBC79B8C2,
  0x300D2F26, 0x3FEEF141,
  0x08DED372, 0xBC82AA1B,
  0xCEF36436, 0x3FD0CD00,
  0x0C93E2B5, 0xBC79FB0A,
  0xFBC0F11C, 0x3FEEE0B1,
  0x80BBC3B1, 0xBC4BFD23,
  0xAA94DDEB, 0x3FD14861,
  0xB5B615A4, 0xBC6BE881,
  0x44D5EFA1, 0x3FEECFA7,
  0x4AF541D0, 0xBC556D0A,
  0x64C6B876, 0x3FD1C37D,
  0xFE0DCFF5, 0x3C746076,
  0x4F76EFA8, 0x3FEEBE21,
  0x12BA543E, 0xBC802F9F,
  0x111AAF36, 0x3FD23E52,
  0x334EFF18, 0xBC74F080,
  0x61BBAF4F, 0x3FEEAC20,
  0x3E94658D, 0x3C62C1D5,
  0xC43EB49F, 0x3FD2B8DD,
  0x99F2D807, 0x3C615538,
  0xC3A7CD83, 0x3FEE99A4,
  0x1BC53CE8, 0xBC82264B,
  0x94049F87, 0x3FD3331E,
  0xB40C302C, 0x3C7E0CB6,
  0xBF29A9ED, 0x3FEE86AE,
  0xFDBB58A7, 0x3C89397A,
  0x9769D3D8, 0x3FD3AD12,
  0x04878398, 0x3C003D55,
  0xA0193D40, 0x3FEE733E,
  0x3546CE13, 0xBC86428B,
  0xE69EE697, 0x3FD426B7,
  0x5705C59F, 0xBC7F09C7,
  0xB436E9D0, 0x3FEE5F54,
  0xD02FC8BC, 0x3C87EB0F,
  0x9B0F3D20, 0x3FD4A00C,
  0x6BB08EAD, 0x3C7823BA,
  0x4B2A449C, 0x3FEE4AF1,
  0x2E8A6833, 0xBC868CA0,
  0xCF68A77A, 0x3FD5190E,
  0x55EEF0F3, 0x3C7B3571,
  0xB680D6A5, 0x3FEE3614,
  0xAA015237, 0xBC727793,
  0x9FA2F597, 0x3FD591BC,
  0xAC3FE0CB, 0x3C67C74B,
  0x49ACD6C1, 0x3FEE20BF,
  0xC7EF636C, 0xBC5660AE,
  0x29078775, 0x3FD60A14,
  0x0BA89133, 0x3C5B1FD8,
  0x5A03DBCE, 0x3FEE0AF1,
  0x02771AE6, 0x3C5FE8E7,
  0x8A38D7F7, 0x3FD68213,
  0x02444AAD, 0xBC7D8892,
  0x3EBD875E, 0x3FEDF4AB,
  0x7E6736C4, 0xBC8E2D8A,
  0xE33A0255, 0x3FD6F9B8,
  0x4EE9DA0D, 0x3C742BC1,
  0x50F228D6, 0x3FEDDDED,
  0xD42BA2BF, 0xBC6E80C8,
  0x55764214, 0x3FD77102,
  0x314BB6CE, 0xBC66EAD7,
  0xEB995912, 0x3FEDC6B7,
  0x776DCD35, 0x3C54B364,
  0x03C86D4E, 0x3FD7E7EE,
  0xDABF5AF2, 0xBC7B63BC,
  0x6B888E83, 0x3FEDAF0B,
  0x2B5E5CEA, 0x3C8A249E,
  0x12826949, 0x3FD85E7A,
  0x9B5FACE0, 0x3C78A40E,
  0x2F71A9DC, 0x3FED96E8,
  0xD5D2039D, 0x3C8FF61B,
  0xA774992F, 0x3FD8D4A4,
  0xEA766326, 0x3C744A02,
  0x97E17B4A, 0x3FED7E4E,
  0x352BED94, 0xBC63B770,
  0xE9F546C5, 0x3FD94A6B,
  0x3E683F58, 0xBC769CE1,
  0x073E4040, 0x3FED653F,
  0x434BEC37, 0xBC876236,
  0x02E80510, 0x3FD9BFCE,
  0xA320B0A4, 0x3C709E39,
  0xE1C619E0, 0x3FED4BB9,
  0x77858F61, 0x3C8F34BB,
  0x1CC50CCA, 0x3FDA34C9,
  0x3B50CECD, 0xBC5A310E,
  0x8D8D7C06, 0x3FED31BF,
  0x3089CBDD, 0x3C7E60DD,
  0x63A09277, 0x3FDAA95B,
  0xB13C0381, 0xBC66293E,
  0x727D94F0, 0x3FED1750,
  0x1EC1A48E, 0x3C80D52B,
  0x05321617, 0x3FDB1D83,
  0xCB99F519, 0xBC7AE242,
  0xFA52AD9F, 0x3FECFC6C,
  0x508F2A0D, 0x3C88B5B5,
  0x30DBAC43, 0x3FDB913E,
  0x2F6C3FF1, 0xBC7E38AD,
  0x909A82E5, 0x3FECE115,
  0xBB31109A, 0x3C81F139,
  0x17B140A3, 0x3FDC048B,
  0x757E9FA7, 0x3C619FE6,
  0xA2B2972E, 0x3FECC54A,
  0x2BA83A98, 0x3C64EE16,
  0xEC7FD19E, 0x3FDC7767,
  0x1A3D5826, 0xBC5EB14D,
  0x9FC67D0B, 0x3FECA90C,
  0x485E3462, 0xBC646A81,
  0xE3D4A51F, 0x3FDCE9D2,
  0x12DAE298, 0xBC62FC8A,
  0xF8CE1A84, 0x3FEC8C5B,
  0xA1590123, 0x3C7AB3D1,
  0x34047661, 0x3FDD5BCA,
  0xA75FC29C, 0x3C728A44,
  0x208BE53B, 0x3FEC6F39,
  0xFBAADB42, 0xBC8741DB,
  0x15329C9A, 0x3FDDCD4C,
  0xE171FD9A, 0x3C70D4C6,
  0x8B8B175E, 0x3FEC51A4,
  0x3B9AA880, 0xBC61BBB4,
  0xC1582A69, 0x3FDE3E56,
  0x1099F88F, 0xBC50A482,
  0xB01DDD81, 0x3FEC339E,
  0xEE82C5C0, 0xBC8CAAF5,
  0x744B05F0, 0x3FDEAEE8,
  0x3C9B027D, 0xBC5789B4,
  0x065B7D50, 0x3FEC1528,
  0x1312E828, 0xBC889211,
  0x6BC4F97B, 0x3FDF1EFF,
  0xF8A7525C, 0x3C717212,
  0x081E7536, 0x3FEBF641,
  0x1628A9A1, 0x3C8B7BD7,
  0xE76ABC97, 0x3FDF8E99,
  0xAF2D00A3, 0x3C59D950,
  0x310294F5, 0x3FEBD6EA,
  0xC88C109D, 0x3C731BBC,
  0x28D2F57A, 0x3FDFFDB6,
  0x2E905B6A, 0x3C6F4A99,
  0xFE630F32, 0x3FEBB723,
  0x452D0A39, 0x3C772BD2,
  0x39C69955, 0x3FE03629,
  0x78397B01, 0xBC82D8CD,
  0xEF58840E, 0x3FEB96EE,
  0xC78FADE0, 0x3C545A3C,
  0x86946E5B, 0x3FE06D36,
  0x4538FF1B, 0x3C83F5AE,
  0x84B704C2, 0x3FEB764B,
  0xC21B389B, 0xBC8F5848,
  0x1E9E1001, 0x3FE0A402,
  0xA13914F6, 0xBC86F643,
  0x410C104E, 0x3FEB553A,
  0x47027A16, 0x3C58FF79,
  0x26B5672E, 0x3FE0DA8B,
  0xF0BEE909, 0xBC8A58DE,
  0xA89C8948, 0x3FEB33BB,
  0x1D1F6CA9, 0x3C8EA6A5,
  0xC4B69C3B, 0x3FE110D0,
  0x98809981, 0x3C8D9189,
  0x4162A4C6, 0x3FEB11D0,
  0x1EFBC0C2, 0x3C71DD56,
  0x1F8B7F82, 0x3FE146D2,
  0x5E2739A8, 0x3C7BF953,
  0x930BD275, 0x3FEAEF78,
  0x79746F94, 0xBC7F8362,
  0x5F2EEDB0, 0x3FE17C8E,
  0x102E2488, 0x3C635E57,
  0x26F69DE5, 0x3FEACCB5,
  0x8DD6B6CC, 0x3C88FB6A,
  0xACB02FDD, 0x3FE1B204,
  0x70CBB5FF, 0xBC5F190C,
  0x88308913, 0x3FEAA986,
  0x07CD5070, 0xBC0B83D6,
  0x3236574C, 0x3FE1E734,
  0xA4F41D5A, 0x3C722A3F,
  0x4373E02D, 0x3FEA85ED,
  0x385EC792, 0x3C69BE06,
  0x1B0394CF, 0x3FE21C1C,
  0x4B23AA31, 0x3C5E5B32,
  0xE72586AF, 0x3FEA61E9,
  0xE2FD453F, 0x3C858330,
  0x93788BBB, 0x3FE250BB,
  0x2457BCCE, 0x3C7EA3D0,
  0x0352BDCF, 0x3FEA3D7D,
  0xECA19669, 0xBC868DBA,
  0xC917A067, 0x3FE28511,
  0xD9A16B70, 0xBC801DF1,
  0x29AEE445, 0x3FEA18A7,
  0x736C0358, 0x3C395E25,
  0xEA88421E, 0x3FE2B91D,
  0xDB216AB0, 0xBC8FA371,
  0xED912F85, 0x3FE9F368,
  0xC5791606, 0xBC81D200,
  0x279A3082, 0x3FE2ECDF,
  0xE0E7E37E, 0x3C8D3557,
  0xE3F25E5C, 0x3FE9CDC2,
  0x12993F62, 0x3C83F991,
  0xB148BC4F, 0x3FE32054,
  0x095A135B, 0x3C8F6B42,
  0xA36A6514, 0x3FE9A7B5,
  0xCC9FA7A9, 0x3C8722CF,
  0xB9BE0367, 0x3FE3537D,
  0x7AF040F0, 0x3C6B327E,
  0xC42E1310, 0x3FE98141,
  0x0488F08D, 0x3C8D1FF8,
  0x7456282B, 0x3FE38659,
  0xA93B07A8, 0xBC710FAD,
  0xE00CB1FD, 0x3FE95A67,
  0xA21F862D, 0xBC80BEFD,
  0x15A2840A, 0x3FE3B8E7,
  0xA7D2F07B, 0xBC797653,
  0x926D9E92, 0x3FE93328,
  0x03600CDA, 0xBC8BB770,
  0xD36CD53A, 0x3FE3EB25,
  0xE1570FC0, 0xBC5BE570,
  0x784DDAF7, 0x3FE90B84,
  0x0AB93B87, 0xBC70FEB1,
  0xE4BA6790, 0x3FE41D14,
  0xD287ECF5, 0x3C84608F,
  0x303D9AD1, 0x3FE8E37C,
  0xB53D4BF8, 0xBC6463A4,
  0x81CF386B, 0x3FE44EB3,
  0x1E6A5505, 0xBC83ED6C,
  0x5A5DC900, 0x3FE8BB10,
  0x3E9474C1, 0x3C8863E0,
  0xE431159F, 0x3FE48000,
  0x7463ED10, 0xBC8B194A,
  0x985D871F, 0x3FE89241,
  0xC413ED84, 0x3C8C48D9,
  0x46AAB761, 0x3FE4B0FC,
  0x738CC59A, 0x3C20DA05,
  0x8D77A6C6, 0x3FE86910,
  0xE2BFE9DD, 0x3C7338FF,
  0xE54ED51B, 0x3FE4E1A4,
  0x89B7C76A, 0xBC8A492F,
  0xDE701CA0, 0x3FE83F7D,
  0x609BC6E8, 0xBC4152CF,
  0xFD7B351C, 0x3FE511F9,
  0x61C48831, 0xBC85C0E8,
  0x31916D5D, 0x3FE8158A,
  0x0B8228DE, 0xBC6DE8B9,
  0xCDDBB724, 0x3FE541FA,
  0x8520D391, 0x3C7232C2,
  0x2EAA1488, 0x3FE7EB36,
  0xA4A5959F, 0x3C5A1D65,
  0x966D59B3, 0x3FE571A6,
  0x4D0FB198, 0x3C5C843B,
  0x7F09E54F, 0x3FE7C082,
  0xD72AEE68, 0xBC6C73D6,
  0x98813A12, 0x3FE5A0FC,
  0xB7D4227B, 0xBC8D82E2,
  0xCD7F6543, 0x3FE7956F,
  0xE9D45AE4, 0xBC8AB276,
  0x16BF8F0D, 0x3FE5CFFC,
  0x70EB578A, 0x3C896CB3,
  0xC655211F, 0x3FE769FE,
  0xCF8C68C5, 0xBC6827D5,
  0x552A9E57, 0x3FE5FEA4,
  0xF7EE20B7, 0x3C80B6CE,
  0x174EFBA1, 0x3FE73E30,
  0x3D94AD5F, 0xBC65D3AE,
  0x9921AC79, 0x3FE62CF4,
  0x55B6241A, 0xBC8EDD98,
  0x6FA77678, 0x3FE71204,
  0xA5029C81, 0x3C8425B0,
  0x2963E755, 0x3FE65AEC,
  0x6B71053C, 0x3C8126F9,
  0x800CF55E, 0x3FE6E57C,
  0xDEDBD0A6, 0x3C860286,
  0x4E134B2F, 0x3FE6888A,
  0x7644D5E6, 0xBC86B7D3,
  0xFA9EFB5D, 0x3FE6B898,
  0x86CCF4B2, 0x3C715AC7,
  0x50B7821A, 0x3FE6B5CE,
  0x8F702E0F, 0xBC65D515,
  0x92EB6253, 0x3FE68B5A,
  0xD985F89C, 0xBC89A91A,
  0x7C40BDE1, 0x3FE6E2B7,
  0x857FAD53, 0xBC70E729,
  0xFDEB8CBA, 0x3FE65DC1,
  0x47337C77, 0xBC597C1B,
  0x1D0A8C40, 0x3FE70F45,
  0x3885770D, 0x3C697EDE,
  0xF20191C7, 0x3FE62FCF,
  0x895756EF, 0x3C6D9143,
  0x80DEA578, 0x3FE73B76,
  0x06DC12A2, 0xBC722483,
  0x26F563DF, 0x3FE60185,
  0xE0E432D0, 0x3C846CA5,
  0xF6F7B524, 0x3FE7674A,
  0x94AC84A8, 0x3C7E9D3F,
  0x55F1F17A, 0x3FE5D2E2,
  0x04C8892B, 0x3C803141,
  0xD0041D52, 0x3FE792C1,
  0xEEB354EB, 0xBC8ABF05,
  0x39824077, 0x3FE5A3E8,
  0x2759BE62, 0x3C8428AA,
  0x5E28B3C2, 0x3FE7BDDA,
  0x7CCD0393, 0x3C4AD119,
  0x8D8E83F2, 0x3FE57497,
  0xAF282D23, 0x3C8F4714,
  0xF5037959, 0x3FE7E893,
  0xAA650C4C, 0x3C80EEFB,
  0x0F592CA5, 0x3FE544F1,
  0xE6C7A62F, 0xBC8E7AE8,
  0xE9AE4BA4, 0x3FE812ED,
  0xDF402DDA, 0xBC87830A,
  0x7D7BF3DA, 0x3FE514F5,
  0x8073C259, 0x3C747A10}
};

typedef union
{
  double value;
  struct
  {
    W32 lsw;
    W32 msw;
  } parts;
} ieee_double_shape_type;

/* CN = 1+2**27 = '41a0000002000000' IEEE double format */
#define  CN   134217729.0


/* Exact addition of two single-length floating point numbers, Dekker. */
/* The macro produces a double-length number (z,zz) that satisfies     */
/* z+zz = x+y exactly.                                                 */

#define  EADD(x,y,z,zz)  \
           z=(x)+(y);  zz=(ABS(x)>ABS(y)) ? (((x)-(z))+(y)) : (((y)-(z))+(x));


/* Exact subtraction of two single-length floating point numbers, Dekker. */
/* The macro produces a double-length number (z,zz) that satisfies        */
/* z+zz = x-y exactly.                                                    */

#define  ESUB(x,y,z,zz)  \
           z=(x)-(y);  zz=(ABS(x)>ABS(y)) ? (((x)-(z))-(y)) : ((x)-((y)+(z)));


/* Exact multiplication of two single-length floating point numbers,   */
/* Veltkamp. The macro produces a double-length number (z,zz) that     */
/* satisfies z+zz = x*y exactly. p,hx,tx,hy,ty are temporary           */
/* storage variables of type double.                                   */

#define  EMULV(x,y,z,zz,p,hx,tx,hy,ty)          \
           p=CN*(x);  hx=((x)-p)+p;  tx=(x)-hx; \
           p=CN*(y);  hy=((y)-p)+p;  ty=(y)-hy; \
           z=(x)*(y); zz=(((hx*hy-z)+hx*ty)+tx*hy)+tx*ty;


/* Exact multiplication of two single-length floating point numbers, Dekker. */
/* The macro produces a nearly double-length number (z,zz) (see Dekker)      */
/* that satisfies z+zz = x*y exactly. p,hx,tx,hy,ty,q are temporary          */
/* storage variables of type double.                                         */

#define  MUL12(x,y,z,zz,p,hx,tx,hy,ty,q)        \
           p=CN*(x);  hx=((x)-p)+p;  tx=(x)-hx; \
           p=CN*(y);  hy=((y)-p)+p;  ty=(y)-hy; \
           p=hx*hy;  q=hx*ty+tx*hy; z=p+q;  zz=((p-z)+q)+tx*ty;


/* Double-length addition, Dekker. The macro produces a double-length   */
/* number (z,zz) which satisfies approximately   z+zz = x+xx + y+yy.    */
/* An error bound: (abs(x+xx)+abs(y+yy))*4.94e-32. (x,xx), (y,yy)       */
/* are assumed to be double-length numbers. r,s are temporary           */
/* storage variables of type double.                                    */

#define  ADD2(x,xx,y,yy,z,zz,r,s)                    \
           r=(x)+(y);  s=(ABS(x)>ABS(y)) ?           \
                       (((((x)-r)+(y))+(yy))+(xx)) : \
                       (((((y)-r)+(x))+(xx))+(yy));  \
           z=r+s;  zz=(r-z)+s;


/* Double-length subtraction, Dekker. The macro produces a double-length  */
/* number (z,zz) which satisfies approximately   z+zz = x+xx - (y+yy).    */
/* An error bound: (abs(x+xx)+abs(y+yy))*4.94e-32. (x,xx), (y,yy)         */
/* are assumed to be double-length numbers. r,s are temporary             */
/* storage variables of type double.                                      */

#define  SUB2(x,xx,y,yy,z,zz,r,s)                    \
           r=(x)-(y);  s=(ABS(x)>ABS(y)) ?           \
                       (((((x)-r)-(y))-(yy))+(xx)) : \
                       ((((x)-((y)+r))+(xx))-(yy));  \
           z=r+s;  zz=(r-z)+s;


/* Double-length multiplication, Dekker. The macro produces a double-length  */
/* number (z,zz) which satisfies approximately   z+zz = (x+xx)*(y+yy).       */
/* An error bound: abs((x+xx)*(y+yy))*1.24e-31. (x,xx), (y,yy)               */
/* are assumed to be double-length numbers. p,hx,tx,hy,ty,q,c,cc are         */
/* temporary storage variables of type double.                               */

#define  MUL2(x,xx,y,yy,z,zz,p,hx,tx,hy,ty,q,c,cc)  \
           MUL12(x,y,c,cc,p,hx,tx,hy,ty,q)          \
           cc=((x)*(yy)+(xx)*(y))+cc;   z=c+cc;   zz=(c-z)+cc;


/* Double-length division, Dekker. The macro produces a double-length        */
/* number (z,zz) which satisfies approximately   z+zz = (x+xx)/(y+yy).       */
/* An error bound: abs((x+xx)/(y+yy))*1.50e-31. (x,xx), (y,yy)               */
/* are assumed to be double-length numbers. p,hx,tx,hy,ty,q,c,cc,u,uu        */
/* are temporary storage variables of type double.                           */

#define  DIV2(x,xx,y,yy,z,zz,p,hx,tx,hy,ty,q,c,cc,u,uu)  \
           c=(x)/(y);   MUL12(c,y,u,uu,p,hx,tx,hy,ty,q)  \
           cc=(((((x)-u)-uu)+(xx))-c*(yy))/(y);   z=c+cc;   zz=(c-z)+cc;


/* Double-length addition, slower but more accurate than ADD2.               */
/* The macro produces a double-length                                        */
/* number (z,zz) which satisfies approximately   z+zz = (x+xx)+(y+yy).       */
/* An error bound: abs(x+xx + y+yy)*1.50e-31. (x,xx), (y,yy)                 */
/* are assumed to be double-length numbers. r,rr,s,ss,u,uu,w                 */
/* are temporary storage variables of type double.                           */

#define  ADD2A(x,xx,y,yy,z,zz,r,rr,s,ss,u,uu,w)                        \
           r=(x)+(y);                                                  \
           if (ABS(x)>ABS(y)) { rr=((x)-r)+(y);  s=(rr+(yy))+(xx); }   \
           else               { rr=((y)-r)+(x);  s=(rr+(xx))+(yy); }   \
           if (rr!=0.0) {                                              \
             z=r+s;  zz=(r-z)+s; }                                     \
           else {                                                      \
             ss=(ABS(xx)>ABS(yy)) ? (((xx)-s)+(yy)) : (((yy)-s)+(xx)); \
             u=r+s;                                                    \
             uu=(ABS(r)>ABS(s))   ? ((r-u)+s)   : ((s-u)+r)  ;         \
             w=uu+ss;  z=u+w;                                          \
             zz=(ABS(u)>ABS(w))   ? ((u-z)+w)   : ((w-z)+u)  ; }


/* Double-length subtraction, slower but more accurate than SUB2.            */
/* The macro produces a double-length                                        */
/* number (z,zz) which satisfies approximately   z+zz = (x+xx)-(y+yy).       */
/* An error bound: abs(x+xx - (y+yy))*1.50e-31. (x,xx), (y,yy)               */
/* are assumed to be double-length numbers. r,rr,s,ss,u,uu,w                 */
/* are temporary storage variables of type double.                           */

#define  SUB2A(x,xx,y,yy,z,zz,r,rr,s,ss,u,uu,w)                        \
           r=(x)-(y);                                                  \
           if (ABS(x)>ABS(y)) { rr=((x)-r)-(y);  s=(rr-(yy))+(xx); }   \
           else               { rr=(x)-((y)+r);  s=(rr+(xx))-(yy); }   \
           if (rr!=0.0) {                                              \
             z=r+s;  zz=(r-z)+s; }                                     \
           else {                                                      \
             ss=(ABS(xx)>ABS(yy)) ? (((xx)-s)-(yy)) : ((xx)-((yy)+s)); \
             u=r+s;                                                    \
             uu=(ABS(r)>ABS(s))   ? ((r-u)+s)   : ((s-u)+r)  ;         \
             w=uu+ss;  z=u+w;                                          \
             zz=(ABS(u)>ABS(w))   ? ((u-z)+w)   : ((w-z)+u)  ; }


// From dosincos.h (THESE ARE DIFFERENT FROM ABOVE!)

namespace dosincos {
  static const mynumber  s3 = {{0x55555555, 0xBFC55555}};/* -0.16666666666666666    */
  static const mynumber ss3 = {{0xE77EE482, 0xBC6553AA}};/* -9.2490366677784492e-18 */
  static const mynumber  s5 = {{0x11110F15, 0x3F811111}};/*  0.008333333333332452   */
  static const mynumber ss5 = {{0xDA488820, 0xBC21AC06}};/* -4.7899996586987931e-19 */
  static const mynumber  s7 = {{0x5816C78D, 0xBF2A019F}};/* -0.00019841261022928957 */
  static const mynumber ss7 = {{0x6A18BF2A, 0x3BCDCEC9}};/*  1.2624077757871259e-20 */
  static const mynumber  c2 = {{0x00000000, 0x3FE00000}};/*  0.5                    */
  static const mynumber cc2 = {{0x00000000, 0xBA282FD8}};/* -1.5264073330037701e-28 */
  static const mynumber  c4 = {{0x55555555, 0xBFA55555}};/* -0.041666666666666664   */
  static const mynumber cc4 = {{0x2FFF257E, 0xBC4554BC}};/* -2.312711276085743e-18  */
  static const mynumber  c6 = {{0x16C16A96, 0x3F56C16C}};/*  0.0013888888888888055  */
  static const mynumber cc6 = {{0xE6346F14, 0xBBD2E846}};/* -1.6015133010194884e-20 */
  static const mynumber  c8 = {{0x821D5987, 0xBEFA019F}};/* -2.480157866754367e-05  */
  static const mynumber cc8 = {{0x72FFE5CC, 0x3B7AB71E}};/*  3.5357416224857556e-22 */
  
  static const mynumber big = {{0x00000000, 0x42c80000}}; /* 52776558133248         */
  
  static const mynumber hp0 = {{0x54442D18, 0x3FF921FB}}; /* PI / 2                 */
  static const mynumber hp1 = {{0x33145C07, 0x3C91A626}}; /* 6.123233995736766e-17  */

  /***********************************************************************/
  /* Routine receive Double-Length number (x+dx) and computing sin(x+dx) */
  /* as Double-Length number and store it at array v .It computes it by  */
  /* arithmetic action on Double-Length numbers                          */
  /*(x+dx) between 0 and PI/4                                            */
  /***********************************************************************/
  
  void __dubsin(double x, double dx, double v[]) {
    double r,s,p,hx,tx,hy,ty,q,c,cc,d,dd,d2,dd2,e,ee,
      sn,ssn,cs,ccs,ds,dss,dc,dcc;
#if 0
    double xx,y,yy,z,zz;
#endif
    mynumber u;
    int4 k;
    
    u.x=x+big.x;
    k = u.i[LOW_HALF]<<2;
    x=x-(u.x-big.x);
    d=x+dx;
    dd=(x-d)+dx;
    /* sin(x+dx)=sin(Xi+t)=sin(Xi)*cos(t) + cos(Xi)sin(t) where t ->0 */
    MUL2(d,dd,d,dd,d2,dd2,p,hx,tx,hy,ty,q,c,cc);
    sn=sincos.x[k];     /*                                  */
    ssn=sincos.x[k+1];  /*      sin(Xi) and cos(Xi)         */
    cs=sincos.x[k+2];   /*                                  */
    ccs=sincos.x[k+3];  /*                                  */
    MUL2(d2,dd2,s7.x,ss7.x,ds,dss,p,hx,tx,hy,ty,q,c,cc);  /* Taylor    */
    ADD2(ds,dss,s5.x,ss5.x,ds,dss,r,s);
    MUL2(d2,dd2,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);      /* series    */
    ADD2(ds,dss,s3.x,ss3.x,ds,dss,r,s);
    MUL2(d2,dd2,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);      /* for sin   */
    MUL2(d,dd,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    ADD2(ds,dss,d,dd,ds,dss,r,s);                         /* ds=sin(t) */

    MUL2(d2,dd2,c8.x,cc8.x,dc,dcc,p,hx,tx,hy,ty,q,c,cc); ;/* Taylor    */
    ADD2(dc,dcc,c6.x,cc6.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);      /* series    */
    ADD2(dc,dcc,c4.x,cc4.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);      /* for cos   */
    ADD2(dc,dcc,c2.x,cc2.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);      /* dc=cos(t) */

    MUL2(cs,ccs,ds,dss,e,ee,p,hx,tx,hy,ty,q,c,cc);
    MUL2(dc,dcc,sn,ssn,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    SUB2(e,ee,dc,dcc,e,ee,r,s);
    ADD2(e,ee,sn,ssn,e,ee,r,s);                    /* e+ee=sin(x+dx) */

    v[0]=e;
    v[1]=ee;
  }
  /**********************************************************************/
  /* Routine receive Double-Length number (x+dx) and computes cos(x+dx) */
  /* as Double-Length number and store it in array v .It computes it by */
  /* arithmetic action on Double-Length numbers                         */
  /*(x+dx) between 0 and PI/4                                           */
  /**********************************************************************/

  void __dubcos(double x, double dx, double v[]) {
    double r,s,p,hx,tx,hy,ty,q,c,cc,d,dd,d2,dd2,e,ee,
      sn,ssn,cs,ccs,ds,dss,dc,dcc;
#if 0
    double xx,y,yy,z,zz;
#endif
    mynumber u;
    int4 k;
    u.x=x+big.x;
    k = u.i[LOW_HALF]<<2;
    x=x-(u.x-big.x);
    d=x+dx;
    dd=(x-d)+dx;  /* cos(x+dx)=cos(Xi+t)=cos(Xi)cos(t) - sin(Xi)sin(t) */
    MUL2(d,dd,d,dd,d2,dd2,p,hx,tx,hy,ty,q,c,cc);
    sn=sincos.x[k];     /*                                  */
    ssn=sincos.x[k+1];  /*      sin(Xi) and cos(Xi)         */
    cs=sincos.x[k+2];   /*                                  */
    ccs=sincos.x[k+3];  /*                                  */
    MUL2(d2,dd2,s7.x,ss7.x,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    ADD2(ds,dss,s5.x,ss5.x,ds,dss,r,s);
    MUL2(d2,dd2,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    ADD2(ds,dss,s3.x,ss3.x,ds,dss,r,s);
    MUL2(d2,dd2,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    MUL2(d,dd,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    ADD2(ds,dss,d,dd,ds,dss,r,s);

    MUL2(d2,dd2,c8.x,cc8.x,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    ADD2(dc,dcc,c6.x,cc6.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    ADD2(dc,dcc,c4.x,cc4.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    ADD2(dc,dcc,c2.x,cc2.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);

    MUL2(cs,ccs,ds,dss,e,ee,p,hx,tx,hy,ty,q,c,cc);
    MUL2(dc,dcc,sn,ssn,dc,dcc,p,hx,tx,hy,ty,q,c,cc);

    MUL2(d2,dd2,s7.x,ss7.x,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    ADD2(ds,dss,s5.x,ss5.x,ds,dss,r,s);
    MUL2(d2,dd2,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    ADD2(ds,dss,s3.x,ss3.x,ds,dss,r,s);
    MUL2(d2,dd2,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    MUL2(d,dd,ds,dss,ds,dss,p,hx,tx,hy,ty,q,c,cc);
    ADD2(ds,dss,d,dd,ds,dss,r,s);
    MUL2(d2,dd2,c8.x,cc8.x,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    ADD2(dc,dcc,c6.x,cc6.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    ADD2(dc,dcc,c4.x,cc4.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    ADD2(dc,dcc,c2.x,cc2.x,dc,dcc,r,s);
    MUL2(d2,dd2,dc,dcc,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    MUL2(sn,ssn,ds,dss,e,ee,p,hx,tx,hy,ty,q,c,cc);
    MUL2(dc,dcc,cs,ccs,dc,dcc,p,hx,tx,hy,ty,q,c,cc);
    ADD2(e,ee,dc,dcc,e,ee,r,s);
    SUB2(cs,ccs,e,ee,e,ee,r,s);

    v[0]=e;
    v[1]=ee;
  }
  /**********************************************************************/
  /* Routine receive Double-Length number (x+dx) and computes cos(x+dx) */
  /* as Double-Length number and store it in array v                    */
  /**********************************************************************/
  void __docos(double x, double dx, double v[]) {
    double y,yy,p,w[2];
    if (x>0) {y=x; yy=dx;}
    else {y=-x; yy=-dx;}
    if (y<0.5*hp0.x)                                 /*  y< PI/4    */
      {__dubcos(y,yy,w); v[0]=w[0]; v[1]=w[1];}
    else if (y<1.5*hp0.x) {                       /* y< 3/4 * PI */
      p=hp0.x-y;  /* p = PI/2 - y */
      yy=hp1.x-yy;
      y=p+yy;
      yy=(p-y)+yy;
      if (y>0) {__dubsin(y,yy,w); v[0]=w[0]; v[1]=w[1];}
      /* cos(x) = sin ( 90 -  x ) */
      else {__dubsin(-y,-yy,w); v[0]=-w[0]; v[1]=-w[1];
      }
    }
    else { /* y>= 3/4 * PI */
      p=2.0*hp0.x-y;    /* p = PI- y */
      yy=2.0*hp1.x-yy;
      y=p+yy;
      yy=(p-y)+yy;
      __dubcos(y,yy,w);
      v[0]=-w[0];
      v[1]=-w[1];
    }
  }
};

static const double
          sn3 = -1.66666666666664880952546298448555E-01,
          sn5 =  8.33333214285722277379541354343671E-03,
          cs2 =  4.99999999999999999999950396842453E-01,
          cs4 = -4.16666666666664434524222570944589E-02,
          cs6 =  1.38888874007937613028114285595617E-03;

namespace dosincos {
  void __dubsin(double x, double dx, double w[]);
  void __docos(double x, double dx, double w[]);
};

namespace mpa {
  double __mpsin(double x, double dx);
  double __mpcos(double x, double dx);
  double __mpsin1(double x);
  double __mpcos1(double x);
};

namespace branred {
  int __branred(double x, double *a, double *aa);
};

static double slow(double x);
static double slow1(double x);
static double slow2(double x);
static double sloww(double x, double dx, double orig);
static double sloww1(double x, double dx, double orig);
static double sloww2(double x, double dx, double orig, int n);
static double bsloww(double x, double dx, double orig, int n);
static double bsloww1(double x, double dx, double orig, int n);
static double bsloww2(double x, double dx, double orig, int n);
static double cslow2(double x);
static double csloww(double x, double dx, double orig);
static double csloww1(double x, double dx, double orig);
static double csloww2(double x, double dx, double orig, int n);

namespace branred {
  static const mynumber  t576 = {{0x00000000, 0x63f00000}};  /* 2 ^ 576  */
  static const mynumber tm600 = {{0x00000000, 0x1a700000}};  /* 2 ^- 600 */
  static const mynumber  tm24 = {{0x00000000, 0x3e700000}};  /* 2 ^- 24  */
  static const mynumber   big = {{0x00000000, 0x43380000}};  /*  6755399441055744      */
  static const mynumber  big1 = {{0x00000000, 0x43580000}};  /* 27021597764222976      */
  static const mynumber   hp0 = {{0x54442D18, 0x3FF921FB}};  /* 1.5707963267948966     */
  static const mynumber   hp1 = {{0x33145C07, 0x3C91A626}};  /* 6.123233995736766e-17  */
  static const mynumber   mp1 = {{0x58000000, 0x3FF921FB}};  /* 1.5707963407039642     */
  static const mynumber   mp2 = {{0x40000000, 0xBE4DDE97}};  /*-1.3909067675399456e-08 */

  static const double toverp[75] = { /*  2/ PI base 24*/
    10680707.0,  7228996.0,  1387004.0,  2578385.0, 16069853.0,
    12639074.0,  9804092.0,  4427841.0, 16666979.0, 11263675.0,
    12935607.0,  2387514.0,  4345298.0, 14681673.0,  3074569.0,
    13734428.0, 16653803.0,  1880361.0, 10960616.0,  8533493.0,
    3062596.0,  8710556.0,  7349940.0,  6258241.0,  3772886.0,
    3769171.0,  3798172.0,  8675211.0, 12450088.0,  3874808.0,
    9961438.0,   366607.0, 15675153.0,  9132554.0,  7151469.0,
    3571407.0,  2607881.0, 12013382.0,  4155038.0,  6285869.0,
    7677882.0, 13102053.0, 15825725.0,   473591.0,  9065106.0,
    15363067.0,  6271263.0,  9264392.0,  5636912.0,  4652155.0,
    7056368.0, 13614112.0, 10155062.0,  1944035.0,  9527646.0,
    15080200.0,  6658437.0,  6231200.0,  6832269.0, 16767104.0,
    5075751.0,  3212806.0,  1398474.0,  7579849.0,  6349435.0,
    12618859.0,  4703257.0, 12806093.0, 14477321.0,  2786137.0,
    12875403.0,  9837734.0, 14528324.0, 13719321.0,   343717.0 };

  static const double split =  134217729.0;

  /*******************************************************************/
  /* Routine  branred() performs range  reduction of a double number */
  /* x into Double length number a+aa,such that                      */
  /* x=n*pi/2+(a+aa), abs(a+aa)<pi/4, n=0,+-1,+-2,....               */
  /* Routine return integer (n mod 4)                                */
  /*******************************************************************/
  int __branred(double x, double *a, double *aa)
  {
    int i,k;
#if 0
    int n;
#endif
    mynumber  u,gor;
#if 0
    mynumber v;
#endif
    double r[6],s,t,sum,b,bb,sum1,sum2,b1,bb1,b2,bb2,x1,x2,t1,t2;

    x*=tm600.x;
    t=x*split;   /* split x to two numbers */
    x1=t-(t-x);
    x2=x-x1;
    sum=0;
    u.x = x1;
    k = (u.i[HIGH_HALF]>>20)&2047;
    k = (k-450)/24;
    if (k<0)
      k=0;
    gor.x = t576.x;
    gor.i[HIGH_HALF] -= ((k*24)<<20);
    for (i=0;i<6;i++)
      { r[i] = x1*toverp[k+i]*gor.x; gor.x *= tm24.x; }
    for (i=0;i<3;i++) {
      s=(r[i]+big.x)-big.x;
      sum+=s;
      r[i]-=s;
    }
    t=0;
    for (i=0;i<6;i++)
      t+=r[5-i];
    bb=(((((r[0]-t)+r[1])+r[2])+r[3])+r[4])+r[5];
    s=(t+big.x)-big.x;
    sum+=s;
    t-=s;
    b=t+bb;
    bb=(t-b)+bb;
    s=(sum+big1.x)-big1.x;
    sum-=s;
    b1=b;
    bb1=bb;
    sum1=sum;
    sum=0;

    u.x = x2;
    k = (u.i[HIGH_HALF]>>20)&2047;
    k = (k-450)/24;
    if (k<0)
      k=0;
    gor.x = t576.x;
    gor.i[HIGH_HALF] -= ((k*24)<<20);
    for (i=0;i<6;i++)
      { r[i] = x2*toverp[k+i]*gor.x; gor.x *= tm24.x; }
    for (i=0;i<3;i++) {
      s=(r[i]+big.x)-big.x;
      sum+=s;
      r[i]-=s;
    }
    t=0;
    for (i=0;i<6;i++)
      t+=r[5-i];
    bb=(((((r[0]-t)+r[1])+r[2])+r[3])+r[4])+r[5];
    s=(t+big.x)-big.x;
    sum+=s;
    t-=s;
    b=t+bb;
    bb=(t-b)+bb;
    s=(sum+big1.x)-big1.x;
    sum-=s;

    b2=b;
    bb2=bb;
    sum2=sum;

    sum=sum1+sum2;
    b=b1+b2;
    bb = (ABS(b1)>ABS(b2))? (b1-b)+b2 : (b2-b)+b1;
    if (b > 0.5)
      {b-=1.0; sum+=1.0;}
    else if (b < -0.5)
      {b+=1.0; sum-=1.0;}
    s=b+(bb+bb1+bb2);
    t=((b-s)+bb)+(bb1+bb2);
    b=s*split;
    t1=b-(b-s);
    t2=s-t1;
    b=s*hp0.x;
    bb=(((t1*mp1.x-b)+t1*mp2.x)+t2*mp1.x)+(t2*mp2.x+s*hp1.x+t*hp0.x);
    s=b+bb;
    t=(b-s)+bb;
    *a=s;
    *aa=t;
    return ((int) sum)&3; /* return quater of unit circle */
  }
}

namespace mpa {
  struct mp_no {/* This structure holds the details of a multi-precision     */
    int e;        /* floating point number, x: d[0] holds its sign (-1,0 or 1) */
    double d[40]; /* e holds its exponent (...,-2,-1,0,1,2,...) and            */
  };        /* d[1]...d[p] hold its mantissa digits. The value of x is,  */
  /* x = d[1]*r**(e-1) + d[2]*r**(e-2) + ... + d[p]*r**(e-p).  */
  /* Here   r = 2**24,   0 <= d[i] < r  and  1 <= p <= 32.     */
  /* p is a global variable. A multi-precision number is       */
  /* always normalized. Namely, d[1] > 0. An exception is      */
  /* a zero which is characterized by d[0] = 0. The terms      */
  /* d[p+1], d[p+2], ... of a none zero number have no         */
  /* significance and so are the terms e, d[1],d[2],...        */
  /* of a zero.                                                */
  
#define  X   x->d
#define  Y   y->d
#define  Z   z->d
#define  EX  x->e
#define  EY  y->e
#define  EZ  z->e

  typedef union { int i[2]; double d; } number;
#define MIN min
#define MAX max

  static const number radix          = {{0x00000000, 0x41700000}}; /* 2**24  */
  static const number radixi         = {{0x00000000, 0x3e700000}}; /* 2**-24 */
  static const number cutter         = {{0x00000000, 0x44b00000}}; /* 2**76  */
  static const number zero           = {{0x00000000, 0x00000000}}; /*  0     */
  static const number one            = {{0x00000000, 0x3ff00000}}; /*  1     */
  static const number mone           = {{0x00000000, 0xbff00000}}; /* -1     */
  static const number two            = {{0x00000000, 0x40000000}}; /*  2     */
  static const number two5           = {{0x00000000, 0x40400000}}; /* 2**5   */
  static const number two10          = {{0x00000000, 0x40900000}}; /* 2**10  */
  static const number two18          = {{0x00000000, 0x41100000}}; /* 2**18  */
  static const number two19          = {{0x00000000, 0x41200000}}; /* 2**19  */
  static const number two23          = {{0x00000000, 0x41600000}}; /* 2**23  */
  static const number two52          = {{0x00000000, 0x43300000}}; /* 2**52  */
  static const number two57          = {{0x00000000, 0x43800000}}; /* 2**57  */
  static const number two71          = {{0x00000000, 0x44600000}}; /* 2**71  */
  static const number twom1032       = {{0x00000000, 0x00000400}}; /* 2**-1032 */

#define  RADIX     radix.d
#define  RADIXI    radixi.d
#define  CUTTER    cutter.d
#define  ZERO      zero.d
#define  ONE       one.d
#define  MONE      mone.d
#define  TWO       two.d
#define  TWO5      two5.d
#define  TWO10     two10.d
#define  TWO18     two18.d
#define  TWO19     two19.d
#define  TWO23     two23.d
#define  TWO52     two52.d
#define  TWO57     two57.d
#define  TWO71     two71.d
#define  TWOM1032  twom1032.d

  /* mcr() compares the sizes of the mantissas of two multiple precision  */
  /* numbers. Mantissas are compared regardless of the signs of the       */
  /* numbers, even if x->d[0] or y->d[0] are zero. Exponents are also     */
  /* disregarded.                                                         */
  static int mcr(const mp_no *x, const mp_no *y, int p) {
    int i;
    for (i=1; i<=p; i++) {
      if      (X[i] == Y[i])  continue;
      else if (X[i] >  Y[i])  return  1;
      else                    return -1; }
    return 0;
  }



  /* acr() compares the absolute values of two multiple precision numbers */
  int __acr(const mp_no *x, const mp_no *y, int p) {
    int i;

    if      (X[0] == ZERO) {
      if    (Y[0] == ZERO) i= 0;
      else                 i=-1;
    }
    else if (Y[0] == ZERO) i= 1;
    else {
      if      (EX >  EY)   i= 1;
      else if (EX <  EY)   i=-1;
      else                 i= mcr(x,y,p);
    }

    return i;
  }


  /* cr90 compares the values of two multiple precision numbers           */
  int  __cr(const mp_no *x, const mp_no *y, int p) {
    int i;

    if      (X[0] > Y[0])  i= 1;
    else if (X[0] < Y[0])  i=-1;
    else if (X[0] < ZERO ) i= __acr(y,x,p);
    else                   i= __acr(x,y,p);

    return i;
  }


  /* Copy a multiple precision number. Set *y=*x. x=y is permissible.      */
  void __cpy(const mp_no *x, mp_no *y, int p) {
    int i;

    EY = EX;
    for (i=0; i <= p; i++)    Y[i] = X[i];

    return;
  }


  /* Copy a multiple precision number x of precision m into a */
  /* multiple precision number y of precision n. In case n>m, */
  /* the digits of y beyond the m'th are set to zero. In case */
  /* n<m, the digits of x beyond the n'th are ignored.        */
  /* x=y is permissible.                                      */

  void __cpymn(const mp_no *x, int m, mp_no *y, int n) {

    int i,k;

    EY = EX;     k=MIN(m,n);
    for (i=0; i <= k; i++)    Y[i] = X[i];
    for (   ; i <= n; i++)    Y[i] = ZERO;

    return;
  }

  /* Convert a multiple precision number *x into a double precision */
  /* number *y, normalized case  (|x| >= 2**(-1022))) */
  static void norm(const mp_no *x, double *y, int p)
  {
#define R  radixi.d
    int i;
#if 0
    int k;
#endif
    double a,c,u,v,z[5];
    if (p<5) {
      if      (p==1) c = X[1];
      else if (p==2) c = X[1] + R* X[2];
      else if (p==3) c = X[1] + R*(X[2]  +   R* X[3]);
      else if (p==4) c =(X[1] + R* X[2]) + R*R*(X[3] + R*X[4]);
    }
    else {
      for (a=ONE, z[1]=X[1]; z[1] != -inf && z[1] && z[1] < TWO23; )
        {a *= TWO;   z[1] *= TWO; }

      for (i=2; i<5; i++) {
        z[i] = X[i]*a;
        u = (z[i] + CUTTER)-CUTTER;
        if  (u > z[i])  u -= RADIX;
        z[i] -= u;
        z[i-1] += u*RADIXI;
      }

      u = (z[3] + TWO71) - TWO71;
      if (u > z[3])   u -= TWO19;
      v = z[3]-u;

      if (v == TWO18) {
        if (z[4] == ZERO) {
          for (i=5; i <= p; i++) {
            if (X[i] == ZERO)   continue;
            else                {z[3] += ONE;   break; }
          }
        }
        else              z[3] += ONE;
      }

      c = (z[1] + R *(z[2] + R * z[3]))/a;
    }

    c *= X[0];

    for (i=1; i<EX; i++)   c *= RADIX;
    for (i=1; i>EX; i--)   c *= RADIXI;

    *y = c;
    return;
#undef R
  }

  /* Convert a multiple precision number *x into a double precision */
  /* number *y, denormalized case  (|x| < 2**(-1022))) */
  static void denorm(const mp_no *x, double *y, int p)
  {
    int i,k;
    double c,u,z[5];
#if 0
    double a,v;
#endif

#define R  radixi.d
    if (EX<-44 || (EX==-44 && X[1]<TWO5))
      { *y=ZERO; return; }

    if      (p==1) {
      if      (EX==-42) {z[1]=X[1]+TWO10;  z[2]=ZERO;  z[3]=ZERO;  k=3;}
      else if (EX==-43) {z[1]=     TWO10;  z[2]=X[1];  z[3]=ZERO;  k=2;}
      else              {z[1]=     TWO10;  z[2]=ZERO;  z[3]=X[1];  k=1;}
    }
    else if (p==2) {
      if      (EX==-42) {z[1]=X[1]+TWO10;  z[2]=X[2];  z[3]=ZERO;  k=3;}
      else if (EX==-43) {z[1]=     TWO10;  z[2]=X[1];  z[3]=X[2];  k=2;}
      else              {z[1]=     TWO10;  z[2]=ZERO;  z[3]=X[1];  k=1;}
    }
    else {
      if      (EX==-42) {z[1]=X[1]+TWO10;  z[2]=X[2];  k=3;}
      else if (EX==-43) {z[1]=     TWO10;  z[2]=X[1];  k=2;}
      else              {z[1]=     TWO10;  z[2]=ZERO;  k=1;}
      z[3] = X[k];
    }

    u = (z[3] + TWO57) - TWO57;
    if  (u > z[3])   u -= TWO5;

    if (u==z[3]) {
      for (i=k+1; i <= p; i++) {
        if (X[i] == ZERO)   continue;
        else {z[3] += ONE;   break; }
      }
    }

    c = X[0]*((z[1] + R*(z[2] + R*z[3])) - TWO10);

    *y = c*TWOM1032;
    return;

#undef R
  }

  /* Convert a multiple precision number *x into a double precision number *y. */
  /* The result is correctly rounded to the nearest/even. *x is left unchanged */

  void __mp_dbl(const mp_no *x, double *y, int p) {
#if 0
    int i,k;
    double a,c,u,v,z[5];
#endif

    if (X[0] == ZERO)  {*y = ZERO;  return; }

    if      (EX> -42)                 norm(x,y,p);
    else if (EX==-42 && X[1]>=TWO10)  norm(x,y,p);
    else                              denorm(x,y,p);
  }


  /* dbl_mp() converts a double precision number x into a multiple precision  */
  /* number *y. If the precision p is too small the result is truncated. x is */
  /* left unchanged.                                                          */

  void __dbl_mp(double x, mp_no *y, int p) {

    int i,n;
    double u;

    /* Sign */
    if      (x == ZERO)  {Y[0] = ZERO;  return; }
    else if (x >  ZERO)   Y[0] = ONE;
    else                 {Y[0] = MONE;  x=-x;   }

    /* Exponent */
    for (EY=1; x >= RADIX; EY += 1)   x *= RADIXI;
    for (      ; x <  ONE;   EY -= 1)   x *= RADIX;

    /* Digits */
    n=MIN(p,4);
    for (i=1; i<=n; i++) {
      u = (x + TWO52) - TWO52;
      if (u>x)   u -= ONE;
      Y[i] = u;     x -= u;    x *= RADIX; }
    for (   ; i<=p; i++)     Y[i] = ZERO;
    return;
  }


  /*  add_magnitudes() adds the magnitudes of *x & *y assuming that           */
  /*  abs(*x) >= abs(*y) > 0.                                                 */
  /* The sign of the sum *z is undefined. x&y may overlap but not x&z or y&z. */
  /* No guard digit is used. The result equals the exact sum, truncated.      */
  /* *x & *y are left unchanged.                                              */

  static void add_magnitudes(const mp_no *x, const mp_no *y, mp_no *z, int p) {

    int i,j,k;

    EZ = EX;

    i=p;    j=p+ EY - EX;    k=p+1;

    if (j<1)
      {__cpy(x,z,p);  return; }
    else   Z[k] = ZERO;

    for (; j>0; i--,j--) {
      Z[k] += X[i] + Y[j];
      if (Z[k] >= RADIX) {
        Z[k]  -= RADIX;
        Z[--k] = ONE; }
      else
        Z[--k] = ZERO;
    }

    for (; i>0; i--) {
      Z[k] += X[i];
      if (Z[k] >= RADIX) {
        Z[k]  -= RADIX;
        Z[--k] = ONE; }
      else
        Z[--k] = ZERO;
    }

    if (Z[1] == ZERO) {
      for (i=1; i<=p; i++)    Z[i] = Z[i+1]; }
    else   EZ += 1;
  }


  /*  sub_magnitudes() subtracts the magnitudes of *x & *y assuming that      */
  /*  abs(*x) > abs(*y) > 0.                                                  */
  /* The sign of the difference *z is undefined. x&y may overlap but not x&z  */
  /* or y&z. One guard digit is used. The error is less than one ulp.         */
  /* *x & *y are left unchanged.                                              */

  static void sub_magnitudes(const mp_no *x, const mp_no *y, mp_no *z, int p) {

    int i,j,k;

    EZ = EX;

    if (EX == EY) {
      i=j=k=p;
      Z[k] = Z[k+1] = ZERO; }
    else {
      j= EX - EY;
      if (j > p)  {__cpy(x,z,p);  return; }
      else {
        i=p;   j=p+1-j;   k=p;
        if (Y[j] > ZERO) {
          Z[k+1] = RADIX - Y[j--];
          Z[k]   = MONE; }
        else {
          Z[k+1] = ZERO;
          Z[k]   = ZERO;   j--;}
      }
    }

    for (; j>0; i--,j--) {
      Z[k] += (X[i] - Y[j]);
      if (Z[k] < ZERO) {
        Z[k]  += RADIX;
        Z[--k] = MONE; }
      else
        Z[--k] = ZERO;
    }

    for (; i>0; i--) {
      Z[k] += X[i];
      if (Z[k] < ZERO) {
        Z[k]  += RADIX;
        Z[--k] = MONE; }
      else
        Z[--k] = ZERO;
    }

    for (i=1; Z[i] == ZERO; i++) ;
    EZ = EZ - i + 1;
    for (k=1; i <= p+1; )
      Z[k++] = Z[i++];
    for (; k <= p; )
      Z[k++] = ZERO;

    return;
  }


  /* Add two multiple precision numbers. Set *z = *x + *y. x&y may overlap  */
  /* but not x&z or y&z. One guard digit is used. The error is less than    */
  /* one ulp. *x & *y are left unchanged.                                   */

  void __add(const mp_no *x, const mp_no *y, mp_no *z, int p) {

    int n;

    if      (X[0] == ZERO)     {__cpy(y,z,p);  return; }
    else if (Y[0] == ZERO)     {__cpy(x,z,p);  return; }

    if (X[0] == Y[0])   {
      if (__acr(x,y,p) > 0)      {add_magnitudes(x,y,z,p);  Z[0] = X[0]; }
      else                     {add_magnitudes(y,x,z,p);  Z[0] = Y[0]; }
    }
    else                       {
      if ((n=__acr(x,y,p)) == 1) {sub_magnitudes(x,y,z,p);  Z[0] = X[0]; }
      else if (n == -1)        {sub_magnitudes(y,x,z,p);  Z[0] = Y[0]; }
      else                      Z[0] = ZERO;
    }
    return;
  }


  /* Subtract two multiple precision numbers. *z is set to *x - *y. x&y may */
  /* overlap but not x&z or y&z. One guard digit is used. The error is      */
  /* less than one ulp. *x & *y are left unchanged.                         */

  void __sub(const mp_no *x, const mp_no *y, mp_no *z, int p) {

    int n;

    if      (X[0] == ZERO)     {__cpy(y,z,p);  Z[0] = -Z[0];  return; }
    else if (Y[0] == ZERO)     {__cpy(x,z,p);                 return; }

    if (X[0] != Y[0])    {
      if (__acr(x,y,p) > 0)      {add_magnitudes(x,y,z,p);  Z[0] =  X[0]; }
      else                     {add_magnitudes(y,x,z,p);  Z[0] = -Y[0]; }
    }
    else                       {
      if ((n=__acr(x,y,p)) == 1) {sub_magnitudes(x,y,z,p);  Z[0] =  X[0]; }
      else if (n == -1)        {sub_magnitudes(y,x,z,p);  Z[0] = -Y[0]; }
      else                      Z[0] = ZERO;
    }
    return;
  }


  /* Multiply two multiple precision numbers. *z is set to *x * *y. x&y      */
  /* may overlap but not x&z or y&z. In case p=1,2,3 the exact result is     */
  /* truncated to p digits. In case p>3 the error is bounded by 1.001 ulp.   */
  /* *x & *y are left unchanged.                                             */

  void __mul(const mp_no *x, const mp_no *y, mp_no *z, int p) {

    int i, i1, i2, j, k, k2;
    double u;

    /* Is z=0? */
    if (X[0]*Y[0]==ZERO)
      { Z[0]=ZERO;  return; }

    /* Multiply, add and carry */
    k2 = (p<3) ? p+p : p+3;
    Z[k2]=ZERO;
    for (k=k2; k>1; ) {
      if (k > p)  {i1=k-p; i2=p+1; }
      else        {i1=1;   i2=k;   }
      for (i=i1,j=i2-1; i<i2; i++,j--)  Z[k] += X[i]*Y[j];

      u = (Z[k] + CUTTER)-CUTTER;
      if  (u > Z[k])  u -= RADIX;
      Z[k]  -= u;
      Z[--k] = u*RADIXI;
    }

    /* Is there a carry beyond the most significant digit? */
    if (Z[1] == ZERO) {
      for (i=1; i<=p; i++)  Z[i]=Z[i+1];
      EZ = EX + EY - 1; }
    else
      EZ = EX + EY;

    Z[0] = X[0] * Y[0];
    return;
  }


  /* Invert a multiple precision number. Set *y = 1 / *x.                     */
  /* Relative error bound = 1.001*r**(1-p) for p=2, 1.063*r**(1-p) for p=3,   */
  /* 2.001*r**(1-p) for p>3.                                                  */
  /* *x=0 is not permissible. *x is left unchanged.                           */

  void __inv(const mp_no *x, mp_no *y, int p) {
    int i;
#if 0
    int l;
#endif
    double t;
    mp_no z,w;
    static const int np1[] = {0,0,0,0,1,2,2,2,2,3,3,3,3,3,3,3,3,3,
                              4,4,4,4,4,4,4,4,4,4,4,4,4,4,4};
    const mp_no mptwo = {1,{1.0,2.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0}};

    __cpy(x,&z,p);  z.e=0;  __mp_dbl(&z,&t,p);
    t=ONE/t;   __dbl_mp(t,y,p);    EY -= EX;

    for (i=0; i<np1[p]; i++) {
      __cpy(y,&w,p);
      __mul(x,&w,y,p);
      __sub(&mptwo,y,&z,p);
      __mul(&w,&z,y,p);
    }
    return;
  }


  /* Divide one multiple precision number by another.Set *z = *x / *y. *x & *y */
  /* are left unchanged. x&y may overlap but not x&z or y&z.                   */
  /* Relative error bound = 2.001*r**(1-p) for p=2, 2.063*r**(1-p) for p=3     */
  /* and 3.001*r**(1-p) for p>3. *y=0 is not permissible.                      */

  void __dvd(const mp_no *x, const mp_no *y, mp_no *z, int p) {

    mp_no w;

    if (X[0] == ZERO)    Z[0] = ZERO;
    else                {__inv(y,&w,p);   __mul(x,&w,z,p);}
    return;
  }
  
#undef  X
#undef  Y
#undef  Z
#undef  EX
#undef  EY
#undef  EZ

  static const number hpinv = {{0x6DC9C883, 0x3FE45F30}}; /*  0.63661977236758138    */
  static const number toint = {{0x00000000, 0x43380000}}; /*  6755399441055744       */

  static const mp_no oofac27 = {-3,{1.0,7.0,4631664.0,12006312.0,13118056.0,6538613.0,646354.0,
                                    8508025.0,9131256.0,7548776.0,2529842.0,8864927.0,660489.0,15595125.0,12777885.0,
                                    11618489.0,13348664.0,5486686.0,514518.0,11275535.0,4727621.0,3575562.0,
                                    13579710.0,5829745.0,7531862.0,9507898.0,6915060.0,4079264.0,1907586.0,
                                    6078398.0,13789314.0,5504104.0,14136.0}};

  static const mp_no pi = {1,{1.0,3.0,
                              2375530.0,8947107.0,578323.0,1673774.0,225395.0,4498441.0,3678761.0,
                              10432976.0,536314.0,10021966.0,7113029.0,2630118.0,3723283.0,7847508.0,
                              6737716.0,15273068.0,12626985.0,12044668.0,5299519.0,8705461.0,11880201.0,
                              1544726.0,14014857.0,7994139.0,13709579.0,10918111.0,11906095.0,16610011.0,
                              13638367.0,12040417.0,11529578.0,2522774.0}};
  
  static const mp_no hp = {1,{1.0, 1.0,
                              9576373.0,4473553.0,8677769.0,9225495.0,112697.0,10637828.0,
                              10227988.0,13605096.0,268157.0,5010983.0,3556514.0,9703667.0,
                              1861641.0,12312362.0,3368858.0,7636534.0,6313492.0,14410942.0,
                              2649759.0,12741338.0,14328708.0,9160971.0,7007428.0,12385677.0,
                              15243397.0,13847663.0,14341655.0,16693613.0,15207791.0,14408816.0,
                              14153397.0,1261387.0,6110792.0,2291862.0,4181138.0,5295267.0}};

  static const double toverp[75] = {
    10680707.0,  7228996.0,  1387004.0,  2578385.0, 16069853.0,
    12639074.0,  9804092.0,  4427841.0, 16666979.0, 11263675.0,
    12935607.0,  2387514.0,  4345298.0, 14681673.0,  3074569.0,
    13734428.0, 16653803.0,  1880361.0, 10960616.0,  8533493.0,
    3062596.0,  8710556.0,  7349940.0,  6258241.0,  3772886.0,
    3769171.0,  3798172.0,  8675211.0, 12450088.0,  3874808.0,
    9961438.0,   366607.0, 15675153.0,  9132554.0,  7151469.0,
    3571407.0,  2607881.0, 12013382.0,  4155038.0,  6285869.0,
    7677882.0, 13102053.0, 15825725.0,   473591.0,  9065106.0,
    15363067.0,  6271263.0,  9264392.0,  5636912.0,  4652155.0,
    7056368.0, 13614112.0, 10155062.0,  1944035.0,  9527646.0,
    15080200.0,  6658437.0,  6231200.0,  6832269.0, 16767104.0,
    5075751.0,  3212806.0,  1398474.0,  7579849.0,  6349435.0,
    12618859.0,  4703257.0, 12806093.0, 14477321.0,  2786137.0,
    12875403.0,  9837734.0, 14528324.0, 13719321.0,   343717.0 };

  /****************************************************************/
  /* Compute Multi-Precision sin() function for given p.  Receive */
  /* Multi  Precision number x and result stored at y             */
  /****************************************************************/
  static void ss32(mp_no *x, mp_no *y, int p) {
    int i;
    double a;
#if 0
    double b;
    static const mp_no mpone = {1,{1.0,1.0}};
#endif
    mp_no mpt1,x2,gor,sum ,mpk={1,{1.0}};
#if 0
    mp_no mpt2;
#endif
    for (i=1;i<=p;i++) mpk.d[i]=0;

    __mul(x,x,&x2,p);
    __cpy(&oofac27,&gor,p);
    __cpy(&gor,&sum,p);
    for (a=27.0;a>1.0;a-=2.0) {
      mpk.d[1]=a*(a-1.0);
      __mul(&gor,&mpk,&mpt1,p);
      __cpy(&mpt1,&gor,p);
      __mul(&x2,&sum,&mpt1,p);
      __sub(&gor,&mpt1,&sum,p);
    }
    __mul(x,&sum,y,p);
  }

  /**********************************************************************/
  /* Compute Multi-Precision cos() function for given p. Receive Multi  */
  /* Precision number x and result stored at y                          */
  /**********************************************************************/
  static void cc32(mp_no *x, mp_no *y, int p) {
    int i;
    double a;
#if 0
    double b;
    static const mp_no mpone = {1,{1.0,1.0}};
#endif
    mp_no mpt1,x2,gor,sum ,mpk={1,{1.0}};
#if 0
    mp_no mpt2;
#endif
    for (i=1;i<=p;i++) mpk.d[i]=0;

    __mul(x,x,&x2,p);
    mpk.d[1]=27.0;
    __mul(&oofac27,&mpk,&gor,p);
    __cpy(&gor,&sum,p);
    for (a=26.0;a>2.0;a-=2.0) {
      mpk.d[1]=a*(a-1.0);
      __mul(&gor,&mpk,&mpt1,p);
      __cpy(&mpt1,&gor,p);
      __mul(&x2,&sum,&mpt1,p);
      __sub(&gor,&mpt1,&sum,p);
    }
    __mul(&x2,&sum,y,p);
  }

  /***************************************************************************/
  /* c32()   computes both sin(x), cos(x) as Multi precision numbers         */
  /***************************************************************************/
  void __c32(mp_no *x, mp_no *y, mp_no *z, int p) {
    static const mp_no mpt={1,{1.0,2.0}}, one={1,{1.0,1.0}};
    mp_no u,t,t1,t2,c,s;
    int i;
    __cpy(x,&u,p);
    u.e=u.e-1;
    cc32(&u,&c,p);
    ss32(&u,&s,p);
    for (i=0;i<24;i++) {
      __mul(&c,&s,&t,p);
      __sub(&s,&t,&t1,p);
      __add(&t1,&t1,&s,p);
      __sub(&mpt,&c,&t1,p);
      __mul(&t1,&c,&t2,p);
      __add(&t2,&t2,&c,p);
    }
    __sub(&one,&c,y,p);
    __cpy(&s,z,p);
  }

  /************************************************************************/
  /*Routine receive double x and two double results of sin(x) and return  */
  /*result which is more accurate                                         */
  /*Computing sin(x) with multi precision routine c32                     */
  /************************************************************************/
  double __sin32(double x, double res, double res1) {
    int p;
    mp_no a,b,c;
    p=32;
    __dbl_mp(res,&a,p);
    __dbl_mp(0.5*(res1-res),&b,p);
    __add(&a,&b,&c,p);
    if (x>0.8)
      { __sub(&hp,&c,&a,p);
      __c32(&a,&b,&c,p);
      }
    else __c32(&c,&a,&b,p);     /* b=sin(0.5*(res+res1))  */
    __dbl_mp(x,&c,p);           /* c = x                  */
    __sub(&b,&c,&a,p);
    /* if a>0 return min(res,res1), otherwise return max(res,res1) */
    if (a.d[0]>0)  return (res<res1)?res:res1;
    else  return (res>res1)?res:res1;
  }

  /************************************************************************/
  /*Routine receive double x and two double results of cos(x) and return  */
  /*result which is more accurate                                         */
  /*Computing cos(x) with multi precision routine c32                     */
  /************************************************************************/
  double __cos32(double x, double res, double res1) {
    int p;
    mp_no a,b,c;
    p=32;
    __dbl_mp(res,&a,p);
    __dbl_mp(0.5*(res1-res),&b,p);
    __add(&a,&b,&c,p);
    if (x>2.4)
      { __sub(&pi,&c,&a,p);
      __c32(&a,&b,&c,p);
      b.d[0]=-b.d[0];
      }
    else if (x>0.8)
      { __sub(&hp,&c,&a,p);
      __c32(&a,&c,&b,p);
      }
    else __c32(&c,&b,&a,p);     /* b=cos(0.5*(res+res1))  */
    __dbl_mp(x,&c,p);    /* c = x                  */
    __sub(&b,&c,&a,p);
    /* if a>0 return max(res,res1), otherwise return min(res,res1) */
    if (a.d[0]>0)  return (res>res1)?res:res1;
    else  return (res<res1)?res:res1;
  }

  /*******************************************************************/
  /*Compute sin(x+dx) as Multi Precision number and return result as */
  /* double                                                          */
  /*******************************************************************/
  double __mpsin(double x, double dx) {
    int p;
    double y;
    mp_no a,b,c;
    p=32;
    __dbl_mp(x,&a,p);
    __dbl_mp(dx,&b,p);
    __add(&a,&b,&c,p);
    if (x>0.8) { __sub(&hp,&c,&a,p); __c32(&a,&b,&c,p); }
    else __c32(&c,&a,&b,p);     /* b = sin(x+dx)     */
    __mp_dbl(&b,&y,p);
    return y;
  }

  /*******************************************************************/
  /* Compute cos()of double-length number (x+dx) as Multi Precision  */
  /* number and return result as double                              */
  /*******************************************************************/
  double __mpcos(double x, double dx) {
    int p;
    double y;
    mp_no a,b,c;
    p=32;
    __dbl_mp(x,&a,p);
    __dbl_mp(dx,&b,p);
    __add(&a,&b,&c,p);
    if (x>0.8)
      { __sub(&hp,&c,&b,p);
      __c32(&b,&c,&a,p);
      }
    else __c32(&c,&a,&b,p);     /* a = cos(x+dx)     */
    __mp_dbl(&a,&y,p);
    return y;
  }

  /******************************************************************/
  /* mpranred() performs range reduction of a double number x into  */
  /* multi precision number y, such that y=x-n*pi/2, abs(y)<pi/4,   */
  /* n=0,+-1,+-2,....                                               */
  /* Return int which indicates in which quarter of circle x is     */
  /******************************************************************/
  int __mpranred(double x, mp_no *y, int p)
  {
    number v;
    double t,xn;
    int i,k,n;
    static const mp_no one = {1,{1.0,1.0}};
    mp_no a,b,c;

    if (ABS(x) < 2.8e14) {
      t = (x*hpinv.d + toint.d);
      xn = t - toint.d;
      v.d = t;
      n =v.i[LOW_HALF]&3;
      __dbl_mp(xn,&a,p);
      __mul(&a,&hp,&b,p);
      __dbl_mp(x,&c,p);
      __sub(&c,&b,y,p);
      return n;
    }
    else {                      /* if x is very big more precision required */
      __dbl_mp(x,&a,p);
      a.d[0]=1.0;
      k = a.e-5;
      if (k < 0) k=0;
      b.e = -k;
      b.d[0] = 1.0;
      for (i=0;i<p;i++) b.d[i+1] = toverp[i+k];
      __mul(&a,&b,&c,p);
      t = c.d[c.e];
      for (i=1;i<=p-c.e;i++) c.d[i]=c.d[i+c.e];
      for (i=p+1-c.e;i<=p;i++) c.d[i]=0;
      c.e=0;
      if (c.d[1] >=  8388608.0)
        { t +=1.0;
        __sub(&c,&one,&b,p);
        __mul(&b,&hp,y,p);
        }
      else __mul(&c,&hp,y,p);
      n = (int) t;
      if (x < 0) { y->d[0] = - y->d[0]; n = -n; }
      return (n&3);
    }
  }

  /*******************************************************************/
  /* Multi-Precision sin() function subroutine, for p=32.  It is     */
  /* based on the routines mpranred() and c32().                     */
  /*******************************************************************/
  double __mpsin1(double x)
  {
    int p;
    int n;
    mp_no u,s,c;
    double y;
    p=32;
    n=__mpranred(x,&u,p);               /* n is 0, 1, 2 or 3 */
    __c32(&u,&c,&s,p);
    switch (n) {                      /* in which quarter of unit circle y is*/
    case 0:
      __mp_dbl(&s,&y,p);
      return y;
      break;

    case 2:
      __mp_dbl(&s,&y,p);
      return -y;
      break;

    case 1:
      __mp_dbl(&c,&y,p);
      return y;
      break;

    case 3:
      __mp_dbl(&c,&y,p);
      return -y;
      break;

    }
    return 0;                     /* unreachable, to make the compiler happy */
  }

  /*****************************************************************/
  /* Multi-Precision cos() function subroutine, for p=32.  It is   */
  /* based  on the routines mpranred() and c32().                  */
  /*****************************************************************/

  double __mpcos1(double x)
  {
    int p;
    int n;
    mp_no u,s,c;
    double y;

    p=32;
    n=__mpranred(x,&u,p);              /* n is 0, 1, 2 or 3 */
    __c32(&u,&c,&s,p);
    switch (n) {                     /* in what quarter of unit circle y is*/

    case 0:
      __mp_dbl(&c,&y,p);
      return y;
      break;

    case 2:
      __mp_dbl(&c,&y,p);
      return -y;
      break;

    case 1:
      __mp_dbl(&s,&y,p);
      return -y;
      break;

    case 3:
      __mp_dbl(&s,&y,p);
      return y;
      break;

    }
    return 0;                     /* unreachable, to make the compiler happy */
  }
  /******************************************************************/

#undef ZERO
#undef ONE
#undef MONE

  void __mptan(double x, mp_no *mpy, int p) {
    static const double MONE = -1.0;
    
    int n;
    mp_no mpw, mpc, mps;
    
    n = __mpranred(x, &mpw, p) & 0x00000001; /* negative or positive result */
    __c32(&mpw, &mpc, &mps, p);              /* computing sin(x) and cos(x) */
    if (n)                     /* second or fourth quarter of unit circle */
      { __dvd(&mpc,&mps,mpy,p);
      mpy->d[0] *= MONE;
      }                          /* tan is negative in this area */
    else  __dvd(&mps,&mpc,mpy,p);
    
    return;
  }

  /* multiple precision stage                                              */
  /* Convert x to multi precision number,compute tan(x) by mptan() routine */
  /* and converts result back to double                                    */
  static double tanMp(double x)
  {
    int p;
    double y;
    mp_no mpy;
    p=32;
    __mptan(x, &mpy, p);
    __mp_dbl(&mpy,&y,p);
    return y;
  }

  double tan(double x) {
  /* polynomial I */
    static const number d3             = {{0x55555555, 0x3FD55555} }; /*  0.333... */
    static const number d5             = {{0x111107C6, 0x3FC11111} }; /*  0.133... */
    static const number d7             = {{0x1CDB8745, 0x3FABA1BA} }; /*    .      */
    static const number d9             = {{0x49CFC666, 0x3F9664ED} }; /*    .      */
    static const number d11            = {{0x3CF2E4EA, 0x3F82385A} }; /*    .      */
  /* polynomial II */
    static const number a3             = {{0x55555555, 0x3fd55555} }; /*  1/3      */
    static const number aa3            = {{0x55555555, 0x3c755555} }; /*  1/3-a3   */
    static const number a5             = {{0x11111111, 0x3fc11111} }; /*  2/15     */
    static const number aa5            = {{0x11111111, 0x3c411111} }; /*  2/15-a5  */
    static const number a7             = {{0x1ba1ba1c, 0x3faba1ba} }; /*  17/315   */
    static const number aa7            = {{0x17917918, 0xbc479179} }; /*   ()-a7   */
    static const number a9             = {{0x882c10fa, 0x3f9664f4} }; /*  62/2835  */
    static const number aa9            = {{0x8b6c44fd, 0xbc09a528} }; /*   ()-a9   */
    static const number a11            = {{0x55e6c23d, 0x3f8226e3} }; /*    .      */
    static const number aa11           = {{0x8f1a2c13, 0xbc2c292b} }; /*    .      */
    static const number a13            = {{0x0e157de0, 0x3f6d6d3d} }; /*    .      */
    static const number aa13           = {{0xc968d971, 0xbc0280cf} }; /*    .      */
    static const number a15            = {{0x452b75e3, 0x3f57da36} }; /*    .      */
#if 0
    static const number aa15           = {{0xb285d2ed, 0xbbf25789} }; /*    .      */
#endif
    static const number a17            = {{0x48036744, 0x3f435582} }; /*    .      */
#if 0
    static const number aa17           = {{0x563f1f23, 0x3be488d9} }; /*    .      */
#endif
    static const number a19            = {{0x734d1664, 0x3f2f57d7} }; /*    .      */
#if 0
    static const number aa19           = {{0x913ccb50, 0x3bb0d55a} }; /*    .      */
#endif
    static const number a21            = {{0x8afcafad, 0x3f1967e1} }; /*    .      */
#if 0
    static const number aa21           = {{0xa42d44e6, 0xbbbd7614} }; /*    .      */
#endif
    static const number a23            = {{0xeea25259, 0x3f0497d8} }; /*    .      */
#if 0
    static const number aa23           = {{0x2e4d2863, 0x3b99f2d0} }; /*    .      */
#endif
    static const number a25            = {{0xd39a6050, 0x3ef0b132} }; /*    .      */
#if 0
    static const number aa25           = {{0xc2c19614, 0x3b93b274} }; /*    .      */
#endif
    static const number a27            = {{0xd3ee24e9, 0x3edb0f72} }; /*    .      */
#if 0
    static const number aa27           = {{0xdd595609, 0x3b61688d} }; /*    .      */
#endif
  /* polynomial III */
    static const number e0             = {{0x55554DBD, 0x3FD55555} }; /*    .      */
    static const number e1             = {{0xE0A6B45F, 0x3FC11112} }; /*    .      */

  /* constants    */
    static const number zero           = {{0x00000000, 0x00000000} }; /* 0         */
    static const number one            = {{0x00000000, 0x3ff00000} }; /* 1         */
    static const number mone           = {{0x00000000, 0xbff00000} }; /*-1         */
    static const number mfftnhf        = {{0x00000000, 0xc02f0000} }; /*-15.5      */
    static const number two8           = {{0x00000000, 0x40700000} }; /* 256       */

    static const number g1             = {{0x00000000, 0x3e4b096c} }; /* 1.259e-8  */
    static const number g2             = {{0x00000000, 0x3faf212d} }; /* 0.0608    */
    static const number g3             = {{0x00000000, 0x3fe92f1a} }; /* 0.787     */
    static const number g4             = {{0x00000000, 0x40390000} }; /* 25.0      */
    static const number g5             = {{0x00000000, 0x4197d784} }; /* 1e8       */
    static const number gy1            = {{0x9abcaf48, 0x3e7ad7f2} }; /* 1e-7      */
    static const number gy2            = {{0x00000000, 0x3faf212d} }; /* 0.0608    */

    static const number u1             = {{0x00000000, 0x3cc8c33a} }; /* 6.873e-16 */
    static const number u2             = {{0x00000000, 0x3983dc4d} }; /* 1.224e-31 */
    static const number u3             = {{0x00000000, 0x3c78e14b} }; /* 2.158e-17 */
    static const number ua3            = {{0x00000000, 0x3bfd8b58} }; /* 1.001e-19 */
    static const number ub3            = {{0x00000000, 0x3cc81898} }; /* 6.688e-16 */
    static const number u4             = {{0x00000000, 0x399856c2} }; /* 3e-31     */
    static const number u5             = {{0x00000000, 0x3c39d80a} }; /* 1.401e-18 */
    static const number u6             = {{0x00000000, 0x3c374c5a} }; /* 1.263e-18 */
    static const number u7             = {{0x00000000, 0x39903beb} }; /* 2.001e-31 */
    static const number u8             = {{0x00000000, 0x399c56ae} }; /* 3.493e-31 */
    static const number u9             = {{0x00000000, 0x3c7d0ac7} }; /* 2.519e-17 */
    static const number ua9            = {{0x00000000, 0x3bfd8b58} }; /* 1.001e-19 */
    static const number ub9            = {{0x00000000, 0x3ccc2375} }; /* 7.810e-16 */
    static const number u10            = {{0x00000000, 0x3c7e40af} }; /* 2.624e-17 */
    static const number ua10           = {{0x00000000, 0x3bfd8b58} }; /* 1.001e-19 */
    static const number ub10           = {{0x00000000, 0x3ccc6405} }; /* 7.880e-16 */
    static const number u11            = {{0x00000000, 0x39e509b6} }; /* 8.298e-30 */
    static const number u12            = {{0x00000000, 0x39e509b6} }; /* 8.298e-30 */
    static const number u13            = {{0x00000000, 0x3c39d80a} }; /* 1.401e-18 */
    static const number u14            = {{0x00000000, 0x3c374c5a} }; /* 1.263e-18 */
    static const number u15            = {{0x00000000, 0x3ab5767a} }; /* 6.935e-26 */
    static const number u16            = {{0x00000000, 0x3ab57744} }; /* 6.936e-26 */
    static const number u17            = {{0x00000000, 0x3c7d0ac7} }; /* 2.519e-17 */
    static const number ua17           = {{0x00000000, 0x3bfdb11f} }; /* 1.006e-19 */
    static const number ub17           = {{0x00000000, 0x3ccc2375} }; /* 7.810e-16 */
    static const number u18            = {{0x00000000, 0x3c7e40af} }; /* 2.624e-17 */
    static const number ua18           = {{0x00000000, 0x3bfdb11f} }; /* 1.006e-19 */
    static const number ub18           = {{0x00000000, 0x3ccc6405} }; /* 7.880e-16 */
    static const number u19            = {{0x00000000, 0x39a13b61} }; /* 4.248e-31 */
    static const number u20            = {{0x00000000, 0x39a13b61} }; /* 4.248e-31 */
    static const number u21            = {{0x00000000, 0x3c3bb9b8} }; /* 1.503e-18 */
    static const number u22            = {{0x00000000, 0x3c392e08} }; /* 1.365e-18 */
    static const number u23            = {{0x00000000, 0x3a0ce706} }; /* 4.560e-29 */
    static const number u24            = {{0x00000000, 0x3a0cff5d} }; /* 4.575e-29 */
    static const number u25            = {{0x00000000, 0x3c7d0ac7} }; /* 2.519e-17 */
    static const number ua25           = {{0x00000000, 0x3bfd8b58} }; /* 1.001e-19 */
    static const number ub25           = {{0x00000000, 0x3ccc2375} }; /* 7.810e-16 */
    static const number u26            = {{0x00000000, 0x3c7e40af} }; /* 2.624e-17 */
    static const number ua26           = {{0x00000000, 0x3bfd8b58} }; /* 1.001e-19 */
    static const number ub26           = {{0x00000000, 0x3ccc6405} }; /* 7.880e-16 */
    static const number u27            = {{0x00000000, 0x3ad421cb} }; /* 2.602e-25 */
    static const number u28            = {{0x00000000, 0x3ad421cb} }; /* 2.602e-25 */

    static const number            mp1 = {{0x58000000, 0x3FF921FB} };
    static const number            mp2 = {{0x3C000000, 0xBE4DDE97} };
    static const number            mp3 = {{0x99D747F2, 0xBC8CB3B3} };
    static const number            pp3 = {{0x98000000, 0xBC8CB3B3} };
    static const number            pp4 = {{0x23e32ed7, 0xbacd747f} };
    static const number          hpinv = {{0x6DC9C883, 0x3FE45F30} };
    static const number          toint = {{0x00000000, 0x43380000} };

#define  ZERO      zero.d
#define  ONE       one.d
#define  MONE      mone.d
#define  TWO8      two8.d

    static const number xfg[186][4] = {                             /* xi,Fi,Gi,FFi, i=16..201 */
      {{{0x1e519d60, 0x3fb00000} },
       {{0x96c4e240, 0x3fb00557} },
       {{0x628127b7, 0x402ff554} },
       {{0x9e355b06, 0xbb9a1dee} },},
      {{{0x1b1a7010, 0x3fb10000} },
       {{0xaab892b7, 0x3fb10668} },
       {{0xbe3fdf74, 0x402e12c7} },
       {{0x037da741, 0x3ba89234} },},
      {{{0x2505e350, 0x3fb20000} },
       {{0xff547824, 0x3fb2079b} },
       {{0xde853633, 0x402c65c5} },
       {{0xe9614250, 0x3bb7486e} },},
      {{{0xfcdc4252, 0x3fb2ffff} },
       {{0x5eb16c68, 0x3fb308f3} },
       {{0xe56be74f, 0x402ae5da} },
       {{0x91a23034, 0xbb82c726} },},
      {{{0xe3ff849f, 0x3fb3ffff} },
       {{0x154999cc, 0x3fb40a71} },
       {{0x046b7352, 0x40298c43} },
       {{0x3843738f, 0x3b9aceaf} },},
      {{{0xedc9590f, 0x3fb4ffff} },
       {{0x429bdd80, 0x3fb50c17} },
       {{0x91b5d674, 0x40285384} },
       {{0xb4403d22, 0xbbc1d02d} },},
      {{{0x00ee83f7, 0x3fb60000} },
       {{0xda80cc21, 0x3fb60de7} },
       {{0xef21a2a7, 0x40273724} },
       {{0x72523ffd, 0xbb95e53c} },},
      {{{0xeb05ea41, 0x3fb6ffff} },
       {{0xb8c51bea, 0x3fb70fe4} },
       {{0xfae562ff, 0x40263370} },
       {{0x8ffe0626, 0xbb99ad0e} },},
      {{{0xdc0515f7, 0x3fb7ffff} },
       {{0x1db54498, 0x3fb81210} },
       {{0x0e7eab5c, 0x40254553} },
       {{0xd62ed686, 0xbb914c87} },},
      {{{0xe384d7ab, 0x3fb8ffff} },
       {{0x2a8d3727, 0x3fb9146c} },
       {{0xfd57f3fd, 0x40246a33} },
       {{0x5381e06d, 0xbbbbda8d} },},
      {{{0xe4832347, 0x3fb9ffff} },
       {{0xd50e1050, 0x3fba16fa} },
       {{0xc5537a96, 0x40239fe2} },
       {{0xc111eabb, 0x3bc7f695} },},
      {{{0x274540e3, 0x3fbb0000} },
       {{0x7ae68517, 0x3fbb19be} },
       {{0x3637e946, 0x4022e481} },
       {{0x8dbd9d93, 0x3bc307f8} },},
      {{{0xfebf2e9b, 0x3fbbffff} },
       {{0x8369cd19, 0x3fbc1cb8} },
       {{0x17aef223, 0x40223676} },
       {{0x424a9cf3, 0x3bc50038} },},
      {{{0x23529045, 0x3fbd0000} },
       {{0xc11d7ef7, 0x3fbd1feb} },
       {{0xb8e43d4e, 0x4021945f} },
       {{0x52a6f224, 0x3b812007} },},
      {{{0xd872a829, 0x3fbdffff} },
       {{0x8ee4d6b7, 0x3fbe2359} },
       {{0x76195d5f, 0x4020fd0c} },
       {{0x85fdca85, 0xbbb4d9ab} },},
      {{{0xff323b84, 0x3fbeffff} },
       {{0xec9073e5, 0x3fbf2704} },
       {{0x3020200f, 0x40206f71} },
       {{0x12836992, 0x3bb77aa2} },},
      {{{0x0ce79195, 0x3fc00000} },
       {{0xbc30cc61, 0x3fc01577} },
       {{0xd6564a88, 0x401fd549} },
       {{0x965c0ad0, 0xbbc8926f} },},
      {{{0xee40e918, 0x3fc07fff} },
       {{0x8279ac01, 0x3fc0978d} },
       {{0x9294bc03, 0x401edbb5} },
       {{0x4aae45d6, 0xbb80a533} },},
      {{{0x0cc091fd, 0x3fc10000} },
       {{0x44dfb2f7, 0x3fc119c5} },
       {{0x067d8e18, 0x401df0bb} },
       {{0x4ff642a4, 0xbbcc2c18} },},
      {{{0x0d9936a1, 0x3fc18000} },
       {{0xb9085a4b, 0x3fc19c1f} },
       {{0x71ce3629, 0x401d131a} },
       {{0x0669355b, 0xbbc36553} },},
      {{{0xed5f3188, 0x3fc1ffff} },
       {{0xee74bf2d, 0x3fc21e9d} },
       {{0xff0cd655, 0x401c41b6} },
       {{0x478ecfc5, 0x3b8867f5} },},
      {{{0x05f06a51, 0x3fc28000} },
       {{0x550b313f, 0x3fc2a141} },
       {{0x1702e6d2, 0x401b7b92} },
       {{0x380131fe, 0xbbadab51} },},
      {{{0xfe3d339e, 0x3fc2ffff} },
       {{0xa75f76df, 0x3fc3240a} },
       {{0xfcb6409d, 0x401abfc8} },
       {{0x0d291d83, 0x3bc60bcf} },},
      {{{0xed888d6f, 0x3fc37fff} },
       {{0x13cc5db7, 0x3fc3a6fb} },
       {{0x8ed5320d, 0x401a0d8f} },
       {{0x4eef03ab, 0x3bb8a48e} },},
      {{{0x02ca050d, 0x3fc40000} },
       {{0xe25776bb, 0x3fc42a13} },
       {{0xfa84c2bc, 0x4019642d} },
       {{0xcc56516f, 0xbbd0bd5d} },},
      {{{0xf2531f5c, 0x3fc47fff} },
       {{0xdeb73404, 0x3fc4ad55} },
       {{0xf86e9035, 0x4018c2fe} },
       {{0x5aa287c8, 0x3b9cffe7} },},
      {{{0x13774992, 0x3fc50000} },
       {{0x7d0ee307, 0x3fc530c2} },
       {{0x370caf35, 0x4018296c} },
       {{0xf91d6532, 0xbbcf75d1} },},
      {{{0xedddcb2d, 0x3fc57fff} },
       {{0x5db4347d, 0x3fc5b45a} },
       {{0x52190c0e, 0x401796ee} },
       {{0x17d5d076, 0x3b88a25f} },},
      {{{0xf41949a0, 0x3fc5ffff} },
       {{0x13bf986a, 0x3fc6381f} },
       {{0x2d2255fd, 0x40170b09} },
       {{0xb1bcd5e7, 0xbb9bfb23} },},
      {{{0xf834d3a1, 0x3fc67fff} },
       {{0x8ec85952, 0x3fc6bc11} },
       {{0x62cf2268, 0x4016854c} },
       {{0x82e39e04, 0x3b9ee53b} },},
      {{{0xfd9106ea, 0x3fc6ffff} },
       {{0xf298f6f7, 0x3fc74032} },
       {{0x1f4f84a9, 0x40160551} },
       {{0x112634b8, 0xbbb59c4a} },},
      {{{0x0f649a4f, 0x3fc78000} },
       {{0x6ca53abc, 0x3fc7c484} },
       {{0x4809d175, 0x40158ab9} },
       {{0x73d3cd2e, 0x3bc91c75} },},
      {{{0xef06bbd8, 0x3fc7ffff} },
       {{0xdf7d76ad, 0x3fc84906} },
       {{0xdd2b30a6, 0x4015152e} },
       {{0x084c3eef, 0xbbbfa2da} },},
      {{{0x021c6334, 0x3fc88000} },
       {{0xd965f986, 0x3fc8cdbb} },
       {{0x51b74296, 0x4014a462} },
       {{0x74dcfe0b, 0xbb9ec02e} },},
      {{{0xf38d0756, 0x3fc8ffff} },
       {{0x28e173c7, 0x3fc952a4} },
       {{0x17b59ebd, 0x4014380b} },
       {{0xb77589f0, 0xbbcd0f1c} },},
      {{{0x104efca1, 0x3fc98000} },
       {{0x4644d23c, 0x3fc9d7c1} },
       {{0xcb1eabd5, 0x4013cfe5} },
       {{0xea188d9e, 0xbbd5d6f7} },},
      {{{0x09417b30, 0x3fca0000} },
       {{0x096d76aa, 0x3fca5d14} },
       {{0xb3723db0, 0x40136bb4} },
       {{0xfbf3979c, 0x3bbe3e0d} },},
      {{{0xeb1c23ec, 0x3fca7fff} },
       {{0xab60288d, 0x3fcae29d} },
       {{0x783071d7, 0x40130b3e} },
       {{0x3d5384bf, 0xbbc7dd82} },},
      {{{0xfb171c13, 0x3fcaffff} },
       {{0xa221a96b, 0x3fcb685f} },
       {{0xd8c0747d, 0x4012ae4d} },
       {{0xd5554972, 0x3bd4644b} },},
      {{{0x0aba44be, 0x3fcb8000} },
       {{0xecdf241f, 0x3fcbee5a} },
       {{0xc6fad63b, 0x401254b1} },
       {{0xd092b85a, 0x3ba41916} },},
      {{{0x113d2a3e, 0x3fcc0000} },
       {{0xb3e92543, 0x3fcc7490} },
       {{0x9a62c035, 0x4011fe3c} },
       {{0x41a03739, 0xbba3cc39} },},
      {{{0xf49e00ce, 0x3fcc7fff} },
       {{0x0f59eab0, 0x3fccfb02} },
       {{0xe956a631, 0x4011aac3} },
       {{0xbfa8cb5b, 0xbbb7a383} },},
      {{{0x05f611ab, 0x3fcd0000} },
       {{0x89e6844e, 0x3fcd81b0} },
       {{0xf391268d, 0x40115a1f} },
       {{0xb2dc91f3, 0x3bd39b5c} },},
      {{{0x14764ceb, 0x3fcd8000} },
       {{0x27debf0d, 0x3fce089d} },
       {{0xfbc84740, 0x40110c2b} },
       {{0x84712510, 0x3bc14d4d} },},
      {{{0x14bcea76, 0x3fce0000} },
       {{0x16dbc820, 0x3fce8fc9} },
       {{0xa00ca48e, 0x4010c0c5} },
       {{0x640f1b9e, 0xbbd33788} },},
      {{{0xfd7995bd, 0x3fce7fff} },
       {{0x88b50424, 0x3fcf1735} },
       {{0xbe02169a, 0x401077cc} },
       {{0x221fdf77, 0xbbb61fee} },},
      {{{0x0cc35436, 0x3fcf0000} },
       {{0xfd21a40b, 0x3fcf9ee3} },
       {{0x1ee7ffe8, 0x40103123} },
       {{0xc79ff5c1, 0x3bd427e3} },},
      {{{0x01d1da33, 0x3fcf8000} },
       {{0xb7dbe15c, 0x3fd0136a} },
       {{0x77d559e5, 0x400fd959} },
       {{0xd67948d7, 0x3bb0c6a1} },},
      {{{0x060c13b2, 0x3fd00000} },
       {{0xaaad4f18, 0x3fd05785} },
       {{0x2675d182, 0x400f549e} },
       {{0x18f0dd10, 0xbbc15208} },},
      {{{0x03885492, 0x3fd04000} },
       {{0x660542d7, 0x3fd09bc3} },
       {{0xdf3f5fec, 0x400ed3e2} },
       {{0xb883ae62, 0xbbd95657} },},
      {{{0x052f5a13, 0x3fd08000} },
       {{0x9a195045, 0x3fd0e024} },
       {{0xfa68f2c8, 0x400e56f8} },
       {{0x5a543e8e, 0x3bded7ba} },},
      {{{0x02ba1af5, 0x3fd0c000} },
       {{0xe2e7f24b, 0x3fd124a9} },
       {{0xbffe633f, 0x400dddb4} },
       {{0x0c60278f, 0xbbdcba86} },},
      {{{0xf76642c1, 0x3fd0ffff} },
       {{0xe162ffe6, 0x3fd16953} },
       {{0x0311d5d5, 0x400d67ed} },
       {{0xe40c5f9e, 0x3b7b1f4a} },},
      {{{0x033602f0, 0x3fd14000} },
       {{0x5f49508e, 0x3fd1ae23} },
       {{0xb8708266, 0x400cf57a} },
       {{0x8620f301, 0xbbd6a6c2} },},
      {{{0xfefd1a13, 0x3fd17fff} },
       {{0xdb2a9ba1, 0x3fd1f318} },
       {{0x8d11009e, 0x400c8639} },
       {{0x69b21d3b, 0x3bd3a9c6} },},
      {{{0xf718365d, 0x3fd1bfff} },
       {{0x0c41e3ac, 0x3fd23835} },
       {{0xe02be47c, 0x400c1a06} },
       {{0x129e8cd1, 0x3bdb961a} },},
      {{{0xff001e00, 0x3fd1ffff} },
       {{0xb2f6395e, 0x3fd27d78} },
       {{0xf2fe9a85, 0x400bb0c1} },
       {{0xe68fd7d8, 0x3be074a9} },},
      {{{0xfe425a6a, 0x3fd23fff} },
       {{0x618faabe, 0x3fd2c2e4} },
       {{0x190b18df, 0x400b4a4c} },
       {{0xf615aad1, 0xbbdf0d1f} },},
      {{{0x059ec1db, 0x3fd28000} },
       {{0xd8583884, 0x3fd30878} },
       {{0x0cd82bc2, 0x400ae688} },
       {{0x141c1f8d, 0xbbd563c3} },},
      {{{0x000dd081, 0x3fd2c000} },
       {{0xaffdb6d8, 0x3fd34e36} },
       {{0x5270fc15, 0x400a855a} },
       {{0x9f2cdafd, 0xbbc6d88d} },},
      {{{0xfc1dcd2b, 0x3fd2ffff} },
       {{0xa95875bc, 0x3fd3941e} },
       {{0xaa9502b6, 0x400a26a8} },
       {{0x8389b15c, 0xbbe13cad} },},
      {{{0xf6c0d4a0, 0x3fd33fff} },
       {{0x739845f5, 0x3fd3da31} },
       {{0x4d2573a0, 0x4009ca5a} },
       {{0xacaee379, 0xbbc71636} },},
      {{{0x06b16793, 0x3fd38000} },
       {{0xdbc088f0, 0x3fd4206f} },
       {{0x9344e33a, 0x40097057} },
       {{0x1d7a4f81, 0xbbc2c052} },},
      {{{0x07358fa3, 0x3fd3c000} },
       {{0x6f23311d, 0x3fd466da} },
       {{0x5aa612ea, 0x4009188a} },
       {{0x685e8edc, 0x3b8653a5} },},
      {{{0xfc3b18cf, 0x3fd3ffff} },
       {{0xe9282e6b, 0x3fd4ad71} },
       {{0x641e643d, 0x4008c2dd} },
       {{0x3f567c64, 0x3b95f0ef} },},
      {{{0x000dd2a8, 0x3fd44000} },
       {{0x1fa3f2d1, 0x3fd4f437} },
       {{0x6072f821, 0x40086f3c} },
       {{0x95ff68b5, 0x3bb68efa} },},
      {{{0xfbb43713, 0x3fd47fff} },
       {{0xb3ac333c, 0x3fd53b2a} },
       {{0x3da56692, 0x40081d94} },
       {{0x2985fd3f, 0xbbbf4d7f} },},
      {{{0xfb113bf4, 0x3fd4bfff} },
       {{0x6e8ed9c2, 0x3fd5824d} },
       {{0xa8add00f, 0x4007cdd2} },
       {{0x1c9b3657, 0x3bcf478a} },},
      {{{0xf7f087c9, 0x3fd4ffff} },
       {{0x07446496, 0x3fd5c9a0} },
       {{0x444588eb, 0x40077fe6} },
       {{0xa4eabb0c, 0xbbc177dc} },},
      {{{0x088b3814, 0x3fd54000} },
       {{0x564125f9, 0x3fd61123} },
       {{0x6281a765, 0x400733be} },
       {{0xf57051c4, 0xbbc2c52c} },},
      {{{0xf7d55966, 0x3fd57fff} },
       {{0xe194a5d5, 0x3fd658d7} },
       {{0x73b47d1f, 0x4006e94b} },
       {{0xf9996dc6, 0x3bda2fcf} },},
      {{{0x08bf2490, 0x3fd5c000} },
       {{0xb775b28d, 0x3fd6a0be} },
       {{0x15b6ec28, 0x4006a07e} },
       {{0xaa5285b8, 0xbbe0ca90} },},
      {{{0x09fa853f, 0x3fd60000} },
       {{0x65a66cfd, 0x3fd6e8d8} },
       {{0x1c701269, 0x40065948} },
       {{0x8591e13a, 0x3bd9ea95} },},
      {{{0x07595fca, 0x3fd64000} },
       {{0xc0556a7c, 0x3fd73125} },
       {{0xbaae9d02, 0x4006139b} },
       {{0x40152b83, 0x3bd88aff} },},
      {{{0x031687da, 0x3fd68000} },
       {{0x92e2cfd0, 0x3fd779a7} },
       {{0xcae0882b, 0x4005cf6b} },
       {{0x9f439451, 0xbbd8a4a2} },},
      {{{0xf5c8cfe2, 0x3fd6bfff} },
       {{0x9fb452ed, 0x3fd7c25e} },
       {{0xc561f1cd, 0x40058cab} },
       {{0xf6a37d74, 0xbbe371a6} },},
      {{{0xf81df231, 0x3fd6ffff} },
       {{0xcfb4dab5, 0x3fd80b4b} },
       {{0x8d3ca5d3, 0x40054b4f} },
       {{0x679dc99f, 0x3bcb4686} },},
      {{{0xfa71385e, 0x3fd73fff} },
       {{0xe007a9b6, 0x3fd8546f} },
       {{0xb3b22176, 0x40050b4b} },
       {{0xa5c73477, 0xbbcd1540} },},
      {{{0x024a9c2b, 0x3fd78000} },
       {{0xa7fcf5cf, 0x3fd89dcb} },
       {{0x3159cbe1, 0x4004cc95} },
       {{0xd58a6ad0, 0xbbdc25ea} },},
      {{{0x02eb62b8, 0x3fd7c000} },
       {{0xec0ba5cf, 0x3fd8e75f} },
       {{0x8731eeea, 0x40048f21} },
       {{0xcc1adafb, 0xbbc1cb73} },},
      {{{0x054a52d1, 0x3fd80000} },
       {{0x8bb822e9, 0x3fd9312d} },
       {{0x9170a729, 0x400452e6} },
       {{0xeac002ee, 0xbbd8bb17} },},
      {{{0xf93a00a3, 0x3fd83fff} },
       {{0x4bb9ad2a, 0x3fd97b35} },
       {{0xae924e7f, 0x400417da} },
       {{0x9a378cc7, 0x3bd4b800} },},
      {{{0xfbdc91c1, 0x3fd87fff} },
       {{0x2771b601, 0x3fd9c578} },
       {{0x78855799, 0x4003ddf4} },
       {{0xa00445d9, 0x3bd9077d} },},
      {{{0xf6d215e6, 0x3fd8bfff} },
       {{0xe0ea4a0b, 0x3fda0ff6} },
       {{0x189a0989, 0x4003a52b} },
       {{0x89c0613d, 0xbbda6831} },},
      {{{0x02f734ef, 0x3fd90000} },
       {{0x736bf579, 0x3fda5ab2} },
       {{0xe9244ca6, 0x40036d75} },
       {{0x4b722377, 0x3be3a6d8} },},
      {{{0x04eef8b4, 0x3fd94000} },
       {{0x9fb6e3d0, 0x3fdaa5ab} },
       {{0xc9089cb7, 0x400336cc} },
       {{0x22cc00bb, 0x3b9f6963} },},
      {{{0x041ec76a, 0x3fd98000} },
       {{0x5176c7e4, 0x3fdaf0e3} },
       {{0xcb0b9506, 0x40030127} },
       {{0x5385a849, 0x3bb1ffdb} },},
      {{{0x08044e47, 0x3fd9c000} },
       {{0x77071224, 0x3fdb3c5a} },
       {{0x50d75ec7, 0x4002cc7f} },
       {{0x78effc8a, 0xbbb0fade} },},
      {{{0x01f8235b, 0x3fda0000} },
       {{0xe725782e, 0x3fdb8811} },
       {{0x18fbfb37, 0x400298cc} },
       {{0x3b50e71b, 0xbbe55ed3} },},
      {{{0xfb8c6f08, 0x3fda3fff} },
       {{0x97b086f3, 0x3fdbd40a} },
       {{0x154de04b, 0x40026607} },
       {{0x455faae3, 0xbbdec65e} },},
      {{{0xfb3d63e1, 0x3fda7fff} },
       {{0x7d9a3b8a, 0x3fdc2045} },
       {{0x7e60bfbb, 0x40023429} },
       {{0x154ebd33, 0x3be3001c} },},
      {{{0xf5f45c48, 0x3fdabfff} },
       {{0x7b8d45e6, 0x3fdc6cc3} },
       {{0xdb1ace69, 0x4002032c} },
       {{0x3ed33616, 0xbbe5ebf8} },},
      {{{0x0508b34c, 0x3fdb0000} },
       {{0xa27e8d37, 0x3fdcb985} },
       {{0xd4459a2b, 0x4001d30a} },
       {{0xae61e2d1, 0xbbd01432} },},
      {{{0x0a84710c, 0x3fdb4000} },
       {{0xc3e50155, 0x3fdd068c} },
       {{0x775034dd, 0x4001a3bd} },
       {{0x58e0e228, 0xbbe80b1e} },},
      {{{0xf692e9d8, 0x3fdb7fff} },
       {{0xc49d6627, 0x3fdd53d9} },
       {{0xfe18066a, 0x4001753e} },
       {{0xf760d33e, 0xbbb004c8} },},
      {{{0x0280f14d, 0x3fdbc000} },
       {{0xe4e81013, 0x3fdda16d} },
       {{0xa38ea052, 0x40014789} },
       {{0x27c9c4ea, 0x3be848bc} },},
      {{{0x001121d1, 0x3fdc0000} },
       {{0xeac018f0, 0x3fddef49} },
       {{0x20b8be0c, 0x40011a98} },
       {{0xd0d6010e, 0xbbe1527e} },},
      {{{0xfef662aa, 0x3fdc3fff} },
       {{0xea0c7070, 0x3fde3d6e} },
       {{0x32f46ccd, 0x4000ee65} },
       {{0x189a000d, 0x3be8d241} },},
      {{{0x09845818, 0x3fdc8000} },
       {{0xf36a8b1b, 0x3fde8bdd} },
       {{0xcac73476, 0x4000c2eb} },
       {{0x12bed284, 0x3bd221f7} },},
      {{{0xfb0493bf, 0x3fdcbfff} },
       {{0xe0c60d10, 0x3fdeda97} },
       {{0x251c7836, 0x40009827} },
       {{0x6eec41b7, 0xbbe0bd54} },},
      {{{0xfd52961f, 0x3fdcffff} },
       {{0xefb3e44b, 0x3fdf299d} },
       {{0x74e459f5, 0x40006e12} },
       {{0xe969c82f, 0xbbd93f77} },},
      {{{0xfe2319a4, 0x3fdd3fff} },
       {{0x17139490, 0x3fdf78f1} },
       {{0x3e737e94, 0x400044a9} },
       {{0x49594b7a, 0xbb91e7cc} },},
      {{{0xfa4de596, 0x3fdd7fff} },
       {{0x638f49e8, 0x3fdfc892} },
       {{0x231057a5, 0x40001be7} },
       {{0xf5af9f5f, 0x3bd482b0} },},
      {{{0xfe729a69, 0x3fddbfff} },
       {{0x7c6ab019, 0x3fe00c41} },
       {{0xbf612660, 0x3fffe78f} },
       {{0x00da681e, 0x3bea5cda} },},
      {{{0x09d66802, 0x3fde0000} },
       {{0xf6b883cf, 0x3fe03461} },
       {{0xbc05a87c, 0x3fff988e} },
       {{0xf2372669, 0xbbe06c33} },},
      {{{0xfb211657, 0x3fde3fff} },
       {{0x191db8e8, 0x3fe05cab} },
       {{0x7bcfe6be, 0x3fff4ac3} },
       {{0x5ed8d35b, 0xbbd5d51f} },},
      {{{0x0a3f068a, 0x3fde8000} },
       {{0x95fb54f0, 0x3fe0851d} },
       {{0x144ca408, 0x3ffefe26} },
       {{0xa2c169c5, 0xbbc7c894} },},
      {{{0x01adb060, 0x3fdec000} },
       {{0xdc7b54f9, 0x3fe0adb9} },
       {{0x5ebe52a7, 0x3ffeb2af} },
       {{0x312c5ffd, 0x3bd4e740} },},
      {{{0xff5c0d01, 0x3fdeffff} },
       {{0x92550a8d, 0x3fe0d680} },
       {{0x0d71fdf0, 0x3ffe6858} },
       {{0x96b35499, 0x3bddd8a6} },},
      {{{0xf93d5fcc, 0x3fdf3fff} },
       {{0x45cb4374, 0x3fe0ff72} },
       {{0x3cce5040, 0x3ffe1f19} },
       {{0x7c1efab4, 0xbbc9f0ec} },},
      {{{0xfa0dd18f, 0x3fdf7fff} },
       {{0x944dd508, 0x3fe1288f} },
       {{0x298b874d, 0x3ffdd6ec} },
       {{0x9642a0a6, 0x3bea6ebd} },},
      {{{0xfd3a9f1a, 0x3fdfbfff} },
       {{0x13750f3e, 0x3fe151d9} },
       {{0x5806a27e, 0x3ffd8fca} },
       {{0xfc65ac7a, 0x3bda2a03} },},
      {{{0xfc481400, 0x3fdfffff} },
       {{0x598944ca, 0x3fe17b4f} },
       {{0x82532170, 0x3ffd49ad} },
       {{0x3d236dc3, 0x3bc4412e} },},
      {{{0xff53786c, 0x3fe01fff} },
       {{0x07d83d47, 0x3fe1a4f3} },
       {{0x851bffeb, 0x3ffd048f} },
       {{0x29f81b14, 0x3bd1589d} },},
      {{{0xfee301b7, 0x3fe03fff} },
       {{0xb8a6a382, 0x3fe1cec4} },
       {{0x7c519db6, 0x3ffcc06a} },
       {{0x5b24d6b2, 0x3bd370e6} },},
      {{{0x006e36bf, 0x3fe06000} },
       {{0x114eb8be, 0x3fe1f8c5} },
       {{0xa34d6786, 0x3ffc7d38} },
       {{0x4b98c1d4, 0xbbea92de} },},
      {{{0xfd60aa43, 0x3fe07fff} },
       {{0xabeccecb, 0x3fe222f4} },
       {{0x77342ac4, 0x3ffc3af4} },
       {{0x03a5c2c2, 0xbbdd47f6} },},
      {{{0x037762e8, 0x3fe0a000} },
       {{0x3f99efe8, 0x3fe24d54} },
       {{0x75f54fab, 0x3ffbf998} },
       {{0x15771a46, 0x3bedf7f4} },},
      {{{0xff1c6921, 0x3fe0bfff} },
       {{0x598e35d0, 0x3fe277e4} },
       {{0x8addd186, 0x3ffbb91f} },
       {{0x5e0e5a73, 0x3be0f16c} },},
      {{{0xff07154b, 0x3fe0dfff} },
       {{0xb6bc3986, 0x3fe2a2a5} },
       {{0x8301646d, 0x3ffb7984} },
       {{0xbbaa5310, 0xbbf02dd0} },},
      {{{0x02fcdda4, 0x3fe10000} },
       {{0x02a59f1e, 0x3fe2cd99} },
       {{0x705219bf, 0x3ffb3ac2} },
       {{0x112fa616, 0xbbe59357} },},
      {{{0x01ce1140, 0x3fe12000} },
       {{0xdf0a67c2, 0x3fe2f8be} },
       {{0x9ab8ae2a, 0x3ffafcd4} },
       {{0x9303f346, 0x3be2c542} },},
      {{{0x04d0f355, 0x3fe14000} },
       {{0x08fcc7bf, 0x3fe32418} },
       {{0x497b9a36, 0x3ffabfb6} },
       {{0xb5a59234, 0x3bebc044} },},
      {{{0x00fb0c8a, 0x3fe16000} },
       {{0x2471618b, 0x3fe34fa5} },
       {{0x0d26d117, 0x3ffa8363} },
       {{0x3f7bb7c9, 0xbbdbfbb2} },},
      {{{0x026f10b3, 0x3fe18000} },
       {{0xf7579056, 0x3fe37b66} },
       {{0x6b4cf4b1, 0x3ffa47d6} },
       {{0xaf0b5de9, 0x3bf0f6b4} },},
      {{{0xfd0978f8, 0x3fe19fff} },
       {{0x290cc78c, 0x3fe3a75e} },
       {{0x36c21315, 0x3ffa0d0c} },
       {{0xa296b262, 0x3beb2129} },},
      {{{0xfd94840b, 0x3fe1bfff} },
       {{0x85b4e4a4, 0x3fe3d38b} },
       {{0x32f2ecef, 0x3ff9d300} },
       {{0xb9bb7d74, 0xbbdbab1a} },},
      {{{0xfbda1ea1, 0x3fe1dfff} },
       {{0xbf3cee2f, 0x3fe3ffef} },
       {{0x6770fed8, 0x3ff999ae} },
       {{0xb4ace9a4, 0x3bda0bdc} },},
      {{{0xfc989533, 0x3fe1ffff} },
       {{0x9c27900c, 0x3fe42c8b} },
       {{0xe0d9f1ac, 0x3ff96112} },
       {{0x2fa2d81a, 0xbbee19eb} },},
      {{{0x012b8d26, 0x3fe22000} },
       {{0xe11975ca, 0x3fe4595f} },
       {{0xcdaa4e80, 0x3ff92929} },
       {{0xacc82d4b, 0x3bf23382} },},
      {{{0x04f4d6af, 0x3fe24000} },
       {{0x4d224131, 0x3fe4866d} },
       {{0x815c34e8, 0x3ff8f1ef} },
       {{0x3b740a99, 0xbbd0c6ff} },},
      {{{0xfcc07bda, 0x3fe25fff} },
       {{0x98b7d010, 0x3fe4b3b4} },
       {{0x73e7ffa1, 0x3ff8bb60} },
       {{0x1ad7a9c2, 0x3bebc31b} },},
      {{{0x042d9639, 0x3fe28000} },
       {{0xb64540d1, 0x3fe4e136} },
       {{0xf4374938, 0x3ff88578} },
       {{0x1b85e901, 0x3be36de9} },},
      {{{0x03be29a0, 0x3fe2a000} },
       {{0x52bffd96, 0x3fe50ef4} },
       {{0xc0042c06, 0x3ff85035} },
       {{0x76f5efbd, 0x3be15d01} },},
      {{{0xfaa91f12, 0x3fe2bfff} },
       {{0x3e2f4e0d, 0x3fe53cee} },
       {{0x8542df07, 0x3ff81b93} },
       {{0x17662a2b, 0x3be555cd} },},
      {{{0xfe884891, 0x3fe2dfff} },
       {{0x6c1a2470, 0x3fe56b25} },
       {{0xe422ea70, 0x3ff7e78e} },
       {{0xbd030c11, 0x3bf03504} },},
      {{{0xfe87152b, 0x3fe2ffff} },
       {{0x9beaaaa1, 0x3fe5999a} },
       {{0xd18fe9b3, 0x3ff7b424} },
       {{0x773e0e64, 0xbb649a5f} },},
      {{{0xffc1a721, 0x3fe31fff} },
       {{0xafe0e564, 0x3fe5c84e} },
       {{0x338db8d4, 0x3ff78152} },
       {{0x5da8e935, 0x3beaf428} },},
      {{{0xff70a372, 0x3fe33fff} },
       {{0x82191d64, 0x3fe5f742} },
       {{0x1122bcae, 0x3ff74f14} },
       {{0xdee4bfaf, 0x3bdb1c4b} },},
      {{{0x0436e836, 0x3fe36000} },
       {{0xfde6ccff, 0x3fe62676} },
       {{0x7644252c, 0x3ff71d67} },
       {{0xe08c3afb, 0xbbec3d10} },},
      {{{0xfcbe9641, 0x3fe37fff} },
       {{0xee9ffdaf, 0x3fe655ec} },
       {{0xa6fc0515, 0x3ff6ec49} },
       {{0x2ed29567, 0x3bdda453} },},
      {{{0xffb6d6ca, 0x3fe39fff} },
       {{0x5e67a1e1, 0x3fe685a5} },
       {{0xbc2ae969, 0x3ff6bbb7} },
       {{0x2ef43882, 0x3becbf7b} },},
      {{{0x04934fec, 0x3fe3c000} },
       {{0x2cc07d75, 0x3fe6b5a1} },
       {{0x10b02ef8, 0x3ff68baf} },
       {{0xfeb7cabd, 0xbbe7c8fb} },},
      {{{0x03f5cf7f, 0x3fe3e000} },
       {{0x3e59def6, 0x3fe6e5e1} },
       {{0x0e61500f, 0x3ff65c2d} },
       {{0x035f7845, 0xbbe30ba4} },},
      {{{0x05280ad9, 0x3fe40000} },
       {{0x91ab4c3e, 0x3fe71666} },
       {{0x19f01c90, 0x3ff62d2f} },
       {{0xffe95f6a, 0xbbf1e9f5} },},
      {{{0x049efb65, 0x3fe42000} },
       {{0x18af3b9d, 0x3fe74732} },
       {{0xb86465e4, 0x3ff5feb2} },
       {{0x280d591e, 0x3bc4cad7} },},
      {{{0x0035ccb6, 0x3fe44000} },
       {{0xcb4ff1e5, 0x3fe77844} },
       {{0x7c455428, 0x3ff5d0b5} },
       {{0x7ba5617c, 0x3bed8c18} },},
      {{{0x03346717, 0x3fe46000} },
       {{0xba258778, 0x3fe7a99f} },
       {{0xf4392254, 0x3ff5a334} },
       {{0xfc84a570, 0xbbefd14a} },},
      {{{0x03002575, 0x3fe48000} },
       {{0xd836768f, 0x3fe7db43} },
       {{0xdcf97e0c, 0x3ff5762e} },
       {{0x5f5df49e, 0xbbdd7eba} },},
      {{{0x055bf381, 0x3fe4a000} },
       {{0x35edeefa, 0x3fe80d32} },
       {{0xea46e31f, 0x3ff549a0} },
       {{0x76823eac, 0xbbdba522} },},
      {{{0x04ce10e3, 0x3fe4c000} },
       {{0xd67dc1a8, 0x3fe83f6b} },
       {{0xed82bcc4, 0x3ff51d88} },
       {{0x077d29ea, 0xbbeae92d} },},
      {{{0x016c60e1, 0x3fe4e000} },
       {{0xca0aaf31, 0x3fe871f1} },
       {{0xbdacbf16, 0x3ff4f1e4} },
       {{0x46ee425e, 0x3be82958} },},
      {{{0xff966f0a, 0x3fe4ffff} },
       {{0x2bff2dae, 0x3fe8a4c5} },
       {{0x3917657e, 0x3ff4c6b2} },
       {{0x5c86c705, 0xbbf127c2} },},
      {{{0x0076e6eb, 0x3fe52000} },
       {{0x175651e8, 0x3fe8d7e7} },
       {{0x4f459b05, 0x3ff49bef} },
       {{0x4181bbfc, 0xbbb1e9d1} },},
      {{{0x03d12d3b, 0x3fe54000} },
       {{0xa976ed56, 0x3fe90b58} },
       {{0xfdf24af4, 0x3ff47199} },
       {{0xc30decaf, 0x3be38c17} },},
      {{{0xfce7fa8d, 0x3fe55fff} },
       {{0xf03a3a09, 0x3fe93f1a} },
       {{0x5f13234b, 0x3ff447b0} },
       {{0x70df7e20, 0x3bf1b8b2} },},
      {{{0x0331b46a, 0x3fe58000} },
       {{0x38e83134, 0x3fe9732f} },
       {{0x68d8b41b, 0x3ff41e30} },
       {{0xb90bc28b, 0xbbee24d8} },},
      {{{0xfc14848e, 0x3fe59fff} },
       {{0x8471b489, 0x3fe9a796} },
       {{0x5de3aa73, 0x3ff3f518} },
       {{0xe0761536, 0xbbecacd9} },},
      {{{0xfb7cd395, 0x3fe5bfff} },
       {{0x24a8b955, 0x3fe9dc52} },
       {{0x4f8fff15, 0x3ff3cc66} },
       {{0x82045611, 0xbbf67c97} },},
      {{{0x000dcc40, 0x3fe5e000} },
       {{0x4df5b93e, 0x3fea1163} },
       {{0x75853228, 0x3ff3a418} },
       {{0xd481f350, 0xbbf585da} },},
      {{{0x02efd2fc, 0x3fe60000} },
       {{0x30d16323, 0x3fea46cb} },
       {{0x187962ae, 0x3ff37c2d} },
       {{0xa5f77bb0, 0x3bf004c3} },},
      {{{0xfeb8088a, 0x3fe61fff} },
       {{0x053920c0, 0x3fea7c8b} },
       {{0x891769a9, 0x3ff354a2} },
       {{0x3fee3029, 0x3bbc6b30} },},
      {{{0x00f3ca06, 0x3fe64000} },
       {{0x28a1911a, 0x3feab2a4} },
       {{0x0a6f0a4a, 0x3ff32d77} },
       {{0xfac5081a, 0x3bf2a6f8} },},
      {{{0xfe9ec2f4, 0x3fe65fff} },
       {{0xd4ce7239, 0x3feae917} },
       {{0x0751a948, 0x3ff306a9} },
       {{0x51ab9dbd, 0xbbe950b5} },},
      {{{0x03d43966, 0x3fe68000} },
       {{0x708b998a, 0x3feb1fe7} },
       {{0xd7a153c7, 0x3ff2e036} },
       {{0xa1e4a14e, 0x3bdd36e2} },},
      {{{0xfab67783, 0x3fe69fff} },
       {{0x2e575464, 0x3feb5714} },
       {{0x05006cb6, 0x3ff2ba1f} },
       {{0x473c2e31, 0x3bea9a4a} },},
      {{{0xfcb65f89, 0x3fe6bfff} },
       {{0x981efd2f, 0x3feb8e9f} },
       {{0xe948d9f7, 0x3ff2945f} },
       {{0xe802df72, 0xbbca5294} },},
      {{{0xfc5609a9, 0x3fe6dfff} },
       {{0xfaed6ff1, 0x3febc68a} },
       {{0x1533411e, 0x3ff26ef8} },
       {{0xf51bc566, 0xbbf89153} },},
      {{{0xfc4eef86, 0x3fe6ffff} },
       {{0xc62205fe, 0x3febfed7} },
       {{0x0e70978c, 0x3ff249e6} },
       {{0xa2b9ff56, 0x3bc39021} },},
      {{{0x004d98b3, 0x3fe72000} },
       {{0x716968ad, 0x3fec3787} },
       {{0x61be7751, 0x3ff22528} },
       {{0x74ee2211, 0x3befc9c5} },},
      {{{0xfc155075, 0x3fe73fff} },
       {{0x5ec6fd4e, 0x3fec709b} },
       {{0xb5d53311, 0x3ff200bd} },
       {{0xa269ae63, 0x3be28a4d} },},
      {{{0x0498c203, 0x3fe76000} },
       {{0x323d08c1, 0x3fecaa15} },
       {{0x93433f65, 0x3ff1dca4} },
       {{0x14a28fb7, 0x3bf8cae4} },},
      {{{0xff1e5636, 0x3fe77fff} },
       {{0x4147c12c, 0x3fece3f6} },
       {{0xbfe294a8, 0x3ff1b8db} },
       {{0x4b56a744, 0xbbe7e19c} },},
      {{{0x0226d45a, 0x3fe7a000} },
       {{0x4120eb7f, 0x3fed1e40} },
       {{0xd15f8278, 0x3ff19561} },
       {{0x032c5d4c, 0x3be64b28} },},
      {{{0x0250a5aa, 0x3fe7c000} },
       {{0xb112a1e1, 0x3fed58f4} },
       {{0x8a59d565, 0x3ff17235} },
       {{0xb8dc7867, 0xbbe716de} },},
      {{{0x0482f82e, 0x3fe7e000} },
       {{0x3576bdf0, 0x3fed9415} },
       {{0xa22a1c5b, 0x3ff14f55} },
       {{0xe1305604, 0x3bf207e1} },},
      {{{0x0205003e, 0x3fe80000} },
       {{0x64d69ff7, 0x3fedcfa3} },
       {{0xe37eb26f, 0x3ff12cc0} },
       {{0xe32395f8, 0xbbd52ec6} },},
      {{{0xfbf99411, 0x3fe81fff} },
       {{0xebf98f51, 0x3fee0ba0} },
       {{0x16ddd5d6, 0x3ff10a76} },
       {{0x59866045, 0xbbece0d6} },},
      {{{0x0248e3a3, 0x3fe84000} },
       {{0x9bb7f565, 0x3fee480f} },
       {{0xfb84e05c, 0x3ff0e873} },
       {{0x1595df92, 0x3bf4e5e8} },},
      {{{0x0145c157, 0x3fe86000} },
       {{0x0a10b3ab, 0x3fee84f1} },
       {{0x7cbd7b1e, 0x3ff0c6b9} },
       {{0xd5f121d0, 0xbbe19de6} },},
      {{{0x022631b9, 0x3fe88000} },
       {{0x0be1f047, 0x3feec247} },
       {{0x6d0b3ee6, 0x3ff0a545} },
       {{0xa3ba2c6f, 0xbbc272b1} },},
      {{{0x045f7828, 0x3fe8a000} },
       {{0x6c45ba1c, 0x3fef0013} },
       {{0xaf2a0f09, 0x3ff08416} },
       {{0x5b63c799, 0x3be82b56} },},
      {{{0xffc686cf, 0x3fe8bfff} },
       {{0xf03c824b, 0x3fef3e57} },
       {{0x33502220, 0x3ff0632c} },
       {{0x2dbeeb25, 0xbbd039ad} },},
      {{{0xfd8644c6, 0x3fe8dfff} },
       {{0x8774261d, 0x3fef7d16} },
       {{0xdd5b3019, 0x3ff04284} },
       {{0xe1eba933, 0x3bd79f33} },},
      {{{0xfe4e7937, 0x3fe8ffff} },
       {{0x1a99a641, 0x3fefbc51} },
       {{0x9f69840b, 0x3ff0221f} },
       {{0x7beee018, 0xbbea9e84} },},
      {{{0x0435251f, 0x3fe92000} },
       {{0x9eb22390, 0x3feffc09} },
       {{0x6f7c51e8, 0x3ff001fb} },
       {{0x31032e0a, 0xbb5a12e7} },}
    };
  
    int ux,i,n;
    double a,da,a2,b,db,c,dc,c1,cc1,c2,cc2,c3,cc3,fi,ffi,gi,pz,s,sy,
      t,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,w,x2,xn,xx2,y,ya,yya,z0,z,zz,z2,zz2;
    int p;
    number num,v;
    mp_no mpa,mpt1,mpt2;
#if 0
    mp_no mpy;
#endif

    int __mpranred(double, mp_no *, int);

    /* x=+-INF, x=NaN */
    num.d = x;  ux = num.i[HIGH_HALF];
    if ((ux&0x7ff00000)==0x7ff00000) return x-x;

    w=(x<ZERO) ? -x : x;

    /* (I) The case abs(x) <= 1.259e-8 */
    if (w<=g1.d)  return x;

    /* (II) The case 1.259e-8 < abs(x) <= 0.0608 */
    if (w<=g2.d) {

      /* First stage */
      x2 = x*x;
      t2 = x*x2*(d3.d+x2*(d5.d+x2*(d7.d+x2*(d9.d+x2*d11.d))));
      if ((y=x+(t2-u1.d*t2)) == x+(t2+u1.d*t2))  return y;

      /* Second stage */
      c1 = x2*(a15.d+x2*(a17.d+x2*(a19.d+x2*(a21.d+x2*(a23.d+x2*(a25.d+
                                                                 x2*a27.d))))));
      EMULV(x,x,x2,xx2,t1,t2,t3,t4,t5)
        ADD2(a13.d,aa13.d,c1,zero.d,c2,cc2,t1,t2)
        MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a11.d,aa11.d,c1,cc1,c2,cc2,t1,t2)
        MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a9.d ,aa9.d ,c1,cc1,c2,cc2,t1,t2)
        MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a7.d ,aa7.d ,c1,cc1,c2,cc2,t1,t2)
        MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a5.d ,aa5.d ,c1,cc1,c2,cc2,t1,t2)
        MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a3.d ,aa3.d ,c1,cc1,c2,cc2,t1,t2)
        MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        MUL2(x ,zero.d,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(x    ,zero.d,c2,cc2,c1,cc1,t1,t2)
        if ((y=c1+(cc1-u2.d*c1)) == c1+(cc1+u2.d*c1))  return y;
      return tanMp(x);
    }

    /* (III) The case 0.0608 < abs(x) <= 0.787 */
    if (w<=g3.d) {

      /* First stage */
      i = ((int) (mfftnhf.d+TWO8*w));
      z = w-xfg[i][0].d;  z2 = z*z;   s = (x<ZERO) ? MONE : ONE;
      pz = z+z*z2*(e0.d+z2*e1.d);
      fi = xfg[i][1].d;   gi = xfg[i][2].d;   t2 = pz*(gi+fi)/(gi-pz);
      if ((y=fi+(t2-fi*u3.d))==fi+(t2+fi*u3.d))  return (s*y);
      t3 = (t2<ZERO) ? -t2 : t2;
      if ((y=fi+(t2-(t4=fi*ua3.d+t3*ub3.d)))==fi+(t2+t4))  return (s*y);

      /* Second stage */
      ffi = xfg[i][3].d;
      c1 = z2*(a7.d+z2*(a9.d+z2*a11.d));
      EMULV(z,z,z2,zz2,t1,t2,t3,t4,t5)
        ADD2(a5.d,aa5.d,c1,zero.d,c2,cc2,t1,t2)
        MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a3.d,aa3.d,c1,cc1,c2,cc2,t1,t2)
        MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        MUL2(z ,zero.d,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(z ,zero.d,c2,cc2,c1,cc1,t1,t2)

        ADD2(fi ,ffi,c1,cc1,c2,cc2,t1,t2)
        MUL2(fi ,ffi,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8)
        SUB2(one.d,zero.d,c3,cc3,c1,cc1,t1,t2)
        DIV2(c2,cc2,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)

        if ((y=c3+(cc3-u4.d*c3))==c3+(cc3+u4.d*c3))  return (s*y);
      return tanMp(x);
    }

    /* (---) The case 0.787 < abs(x) <= 25 */
    if (w<=g4.d) {
      /* Range reduction by algorithm i */
      t = (x*hpinv.d + toint.d);
      xn = t - toint.d;
      v.d = t;
      t1 = (x - xn*mp1.d) - xn*mp2.d;
      n =v.i[LOW_HALF] & 0x00000001;
      da = xn*mp3.d;
      a=t1-da;
      da = (t1-a)-da;
      if (a<ZERO)  {ya=-a;  yya=-da;  sy=MONE;}
      else         {ya= a;  yya= da;  sy= ONE;}

      /* (IV),(V) The case 0.787 < abs(x) <= 25,    abs(y) <= 1e-7 */
      if (ya<=gy1.d)  return tanMp(x);

      /* (VI) The case 0.787 < abs(x) <= 25,    1e-7 < abs(y) <= 0.0608 */
      if (ya<=gy2.d) {
        a2 = a*a;
        t2 = da+a*a2*(d3.d+a2*(d5.d+a2*(d7.d+a2*(d9.d+a2*d11.d))));
        if (n) {
          /* First stage -cot */
          EADD(a,t2,b,db)
            DIV2(one.d,zero.d,b,db,c,dc,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
            if ((y=c+(dc-u6.d*c))==c+(dc+u6.d*c))  return (-y); }
        else {
          /* First stage tan */
          if ((y=a+(t2-u5.d*a))==a+(t2+u5.d*a))  return y; }
        /* Second stage */
        /* Range reduction by algorithm ii */
        t = (x*hpinv.d + toint.d);
        xn = t - toint.d;
        v.d = t;
        t1 = (x - xn*mp1.d) - xn*mp2.d;
        n =v.i[LOW_HALF] & 0x00000001;
        da = xn*pp3.d;
        t=t1-da;
        da = (t1-t)-da;
        t1 = xn*pp4.d;
        a = t - t1;
        da = ((t-a)-t1)+da;

        /* Second stage */
        EADD(a,da,t1,t2)   a=t1;  da=t2;
        MUL2(a,da,a,da,x2,xx2,t1,t2,t3,t4,t5,t6,t7,t8)
          c1 = x2*(a15.d+x2*(a17.d+x2*(a19.d+x2*(a21.d+x2*(a23.d+x2*(a25.d+
                                                                     x2*a27.d))))));
        ADD2(a13.d,aa13.d,c1,zero.d,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a11.d,aa11.d,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a9.d ,aa9.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a7.d ,aa7.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a5.d ,aa5.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a3.d ,aa3.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          MUL2(a ,da ,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a  ,da  ,c2,cc2,c1,cc1,t1,t2)

          if (n) {
            /* Second stage -cot */
            DIV2(one.d,zero.d,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
              if ((y=c2+(cc2-u8.d*c2)) == c2+(cc2+u8.d*c2))  return (-y); }
          else {
            /* Second stage tan */
            if ((y=c1+(cc1-u7.d*c1)) == c1+(cc1+u7.d*c1))  return y; }
        return tanMp(x);
      }

      /* (VII) The case 0.787 < abs(x) <= 25,    0.0608 < abs(y) <= 0.787 */

      /* First stage */
      i = ((int) (mfftnhf.d+TWO8*ya));
      z = (z0=(ya-xfg[i][0].d))+yya;  z2 = z*z;
      pz = z+z*z2*(e0.d+z2*e1.d);
      fi = xfg[i][1].d;   gi = xfg[i][2].d;

      if (n) {
        /* -cot */
        t2 = pz*(fi+gi)/(fi+pz);
        if ((y=gi-(t2-gi*u10.d))==gi-(t2+gi*u10.d))  return (-sy*y);
        t3 = (t2<ZERO) ? -t2 : t2;
        if ((y=gi-(t2-(t4=gi*ua10.d+t3*ub10.d)))==gi-(t2+t4))  return (-sy*y); }
      else   {
        /* tan */
        t2 = pz*(gi+fi)/(gi-pz);
        if ((y=fi+(t2-fi*u9.d))==fi+(t2+fi*u9.d))  return (sy*y);
        t3 = (t2<ZERO) ? -t2 : t2;
        if ((y=fi+(t2-(t4=fi*ua9.d+t3*ub9.d)))==fi+(t2+t4))  return (sy*y); }

      /* Second stage */
      ffi = xfg[i][3].d;
      EADD(z0,yya,z,zz)
        MUL2(z,zz,z,zz,z2,zz2,t1,t2,t3,t4,t5,t6,t7,t8)
        c1 = z2*(a7.d+z2*(a9.d+z2*a11.d));
      ADD2(a5.d,aa5.d,c1,zero.d,c2,cc2,t1,t2)
        MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a3.d,aa3.d,c1,cc1,c2,cc2,t1,t2)
        MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        MUL2(z ,zz ,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(z ,zz ,c2,cc2,c1,cc1,t1,t2)

        ADD2(fi ,ffi,c1,cc1,c2,cc2,t1,t2)
        MUL2(fi ,ffi,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8)
        SUB2(one.d,zero.d,c3,cc3,c1,cc1,t1,t2)

        if (n) {
          /* -cot */
          DIV2(c1,cc1,c2,cc2,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
            if ((y=c3+(cc3-u12.d*c3))==c3+(cc3+u12.d*c3))  return (-sy*y); }
        else {
          /* tan */
          DIV2(c2,cc2,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
            if ((y=c3+(cc3-u11.d*c3))==c3+(cc3+u11.d*c3))  return (sy*y); }

      return tanMp(x);
    }

    /* (---) The case 25 < abs(x) <= 1e8 */
    if (w<=g5.d) {
      /* Range reduction by algorithm ii */
      t = (x*hpinv.d + toint.d);
      xn = t - toint.d;
      v.d = t;
      t1 = (x - xn*mp1.d) - xn*mp2.d;
      n =v.i[LOW_HALF] & 0x00000001;
      da = xn*pp3.d;
      t=t1-da;
      da = (t1-t)-da;
      t1 = xn*pp4.d;
      a = t - t1;
      da = ((t-a)-t1)+da;
      EADD(a,da,t1,t2)   a=t1;  da=t2;
      if (a<ZERO)  {ya=-a;  yya=-da;  sy=MONE;}
      else         {ya= a;  yya= da;  sy= ONE;}

      /* (+++) The case 25 < abs(x) <= 1e8,    abs(y) <= 1e-7 */
      if (ya<=gy1.d)  return tanMp(x);

      /* (VIII) The case 25 < abs(x) <= 1e8,    1e-7 < abs(y) <= 0.0608 */
      if (ya<=gy2.d) {
        a2 = a*a;
        t2 = da+a*a2*(d3.d+a2*(d5.d+a2*(d7.d+a2*(d9.d+a2*d11.d))));
        if (n) {
          /* First stage -cot */
          EADD(a,t2,b,db)
            DIV2(one.d,zero.d,b,db,c,dc,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
            if ((y=c+(dc-u14.d*c))==c+(dc+u14.d*c))  return (-y); }
        else {
          /* First stage tan */
          if ((y=a+(t2-u13.d*a))==a+(t2+u13.d*a))  return y; }

        /* Second stage */
        MUL2(a,da,a,da,x2,xx2,t1,t2,t3,t4,t5,t6,t7,t8)
          c1 = x2*(a15.d+x2*(a17.d+x2*(a19.d+x2*(a21.d+x2*(a23.d+x2*(a25.d+
                                                                     x2*a27.d))))));
        ADD2(a13.d,aa13.d,c1,zero.d,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a11.d,aa11.d,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a9.d ,aa9.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a7.d ,aa7.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a5.d ,aa5.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a3.d ,aa3.d ,c1,cc1,c2,cc2,t1,t2)
          MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
          MUL2(a ,da ,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
          ADD2(a  ,da  ,c2,cc2,c1,cc1,t1,t2)

          if (n) {
            /* Second stage -cot */
            DIV2(one.d,zero.d,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
              if ((y=c2+(cc2-u16.d*c2)) == c2+(cc2+u16.d*c2))  return (-y); }
          else {
            /* Second stage tan */
            if ((y=c1+(cc1-u15.d*c1)) == c1+(cc1+u15.d*c1))  return (y); }
        return tanMp(x);
      }

      /* (IX) The case 25 < abs(x) <= 1e8,    0.0608 < abs(y) <= 0.787 */
      /* First stage */
      i = ((int) (mfftnhf.d+TWO8*ya));
      z = (z0=(ya-xfg[i][0].d))+yya;  z2 = z*z;
      pz = z+z*z2*(e0.d+z2*e1.d);
      fi = xfg[i][1].d;   gi = xfg[i][2].d;

      if (n) {
        /* -cot */
        t2 = pz*(fi+gi)/(fi+pz);
        if ((y=gi-(t2-gi*u18.d))==gi-(t2+gi*u18.d))  return (-sy*y);
        t3 = (t2<ZERO) ? -t2 : t2;
        if ((y=gi-(t2-(t4=gi*ua18.d+t3*ub18.d)))==gi-(t2+t4))  return (-sy*y); }
      else   {
        /* tan */
        t2 = pz*(gi+fi)/(gi-pz);
        if ((y=fi+(t2-fi*u17.d))==fi+(t2+fi*u17.d))  return (sy*y);
        t3 = (t2<ZERO) ? -t2 : t2;
        if ((y=fi+(t2-(t4=fi*ua17.d+t3*ub17.d)))==fi+(t2+t4))  return (sy*y); }

      /* Second stage */
      ffi = xfg[i][3].d;
      EADD(z0,yya,z,zz)
        MUL2(z,zz,z,zz,z2,zz2,t1,t2,t3,t4,t5,t6,t7,t8)
        c1 = z2*(a7.d+z2*(a9.d+z2*a11.d));
      ADD2(a5.d,aa5.d,c1,zero.d,c2,cc2,t1,t2)
        MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(a3.d,aa3.d,c1,cc1,c2,cc2,t1,t2)
        MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
        MUL2(z ,zz ,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
        ADD2(z ,zz ,c2,cc2,c1,cc1,t1,t2)

        ADD2(fi ,ffi,c1,cc1,c2,cc2,t1,t2)
        MUL2(fi ,ffi,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8)
        SUB2(one.d,zero.d,c3,cc3,c1,cc1,t1,t2)

        if (n) {
          /* -cot */
          DIV2(c1,cc1,c2,cc2,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
            if ((y=c3+(cc3-u20.d*c3))==c3+(cc3+u20.d*c3))  return (-sy*y); }
        else {
          /* tan */
          DIV2(c2,cc2,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
            if ((y=c3+(cc3-u19.d*c3))==c3+(cc3+u19.d*c3))  return (sy*y); }
      return tanMp(x);
    }

    /* (---) The case 1e8 < abs(x) < 2**1024 */
    /* Range reduction by algorithm iii */
    n = (branred::__branred(x,&a,&da)) & 0x00000001;
    EADD(a,da,t1,t2)   a=t1;  da=t2;
    if (a<ZERO)  {ya=-a;  yya=-da;  sy=MONE;}
    else         {ya= a;  yya= da;  sy= ONE;}

    /* (+++) The case 1e8 < abs(x) < 2**1024,    abs(y) <= 1e-7 */
    if (ya<=gy1.d)  return tanMp(x);

    /* (X) The case 1e8 < abs(x) < 2**1024,    1e-7 < abs(y) <= 0.0608 */
    if (ya<=gy2.d) {
      a2 = a*a;
      t2 = da+a*a2*(d3.d+a2*(d5.d+a2*(d7.d+a2*(d9.d+a2*d11.d))));
      if (n) {
        /* First stage -cot */
        EADD(a,t2,b,db)
          DIV2(one.d,zero.d,b,db,c,dc,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
          if ((y=c+(dc-u22.d*c))==c+(dc+u22.d*c)) return (-y);
      } else {
        /* First stage tan */
        if ((y=a+(t2-u21.d*a))==a+(t2+u21.d*a)) return y;
      }

      /* Second stage */
      /* Reduction by algorithm iv */
      p=10;    n = (__mpranred(x,&mpa,p)) & 0x00000001;
      __mp_dbl(&mpa,&a,p);        __dbl_mp(a,&mpt1,p);
      __sub(&mpa,&mpt1,&mpt2,p);  __mp_dbl(&mpt2,&da,p);

      MUL2(a,da,a,da,x2,xx2,t1,t2,t3,t4,t5,t6,t7,t8)
        c1 = x2*(a15.d+x2*(a17.d+x2*(a19.d+x2*(a21.d+x2*(a23.d+x2*(a25.d+x2*a27.d))))));
      ADD2(a13.d,aa13.d,c1,zero.d,c2,cc2,t1,t2)
      MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
      ADD2(a11.d,aa11.d,c1,cc1,c2,cc2,t1,t2)
      MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
      ADD2(a9.d ,aa9.d ,c1,cc1,c2,cc2,t1,t2)
      MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
      ADD2(a7.d ,aa7.d ,c1,cc1,c2,cc2,t1,t2)
      MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
      ADD2(a5.d ,aa5.d ,c1,cc1,c2,cc2,t1,t2)
      MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
      ADD2(a3.d ,aa3.d ,c1,cc1,c2,cc2,t1,t2)
      MUL2(x2,xx2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
      MUL2(a ,da ,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
      ADD2(a    ,da    ,c2,cc2,c1,cc1,t1,t2)

      if (n) {
        /* Second stage -cot */
        DIV2(one.d,zero.d,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
          if ((y=c2+(cc2-u24.d*c2)) == c2+(cc2+u24.d*c2)) return (-y);
      } else {
        /* Second stage tan */
        if ((y=c1+(cc1-u23.d*c1)) == c1+(cc1+u23.d*c1)) return y;
      }
      return tanMp(x);
    }

    /* (XI) The case 1e8 < abs(x) < 2**1024,    0.0608 < abs(y) <= 0.787 */
    /* First stage */
    i = ((int) (mfftnhf.d+TWO8*ya));
    z = (z0=(ya-xfg[i][0].d))+yya;  z2 = z*z;
    pz = z+z*z2*(e0.d+z2*e1.d);
    fi = xfg[i][1].d;   gi = xfg[i][2].d;

    if (n) {
      /* -cot */
      t2 = pz*(fi+gi)/(fi+pz);
      if ((y=gi-(t2-gi*u26.d))==gi-(t2+gi*u26.d))  return (-sy*y);
      t3 = (t2<ZERO) ? -t2 : t2;
      if ((y=gi-(t2-(t4=gi*ua26.d+t3*ub26.d)))==gi-(t2+t4))  return (-sy*y);
    } else {
      /* tan */
      t2 = pz*(gi+fi)/(gi-pz);
      if ((y=fi+(t2-fi*u25.d))==fi+(t2+fi*u25.d))  return (sy*y);
      t3 = (t2<ZERO) ? -t2 : t2;
      if ((y=fi+(t2-(t4=fi*ua25.d+t3*ub25.d)))==fi+(t2+t4))  return (sy*y);
    }

    /* Second stage */
    ffi = xfg[i][3].d;
    EADD(z0,yya,z,zz)
    MUL2(z,zz,z,zz,z2,zz2,t1,t2,t3,t4,t5,t6,t7,t8)
    c1 = z2*(a7.d+z2*(a9.d+z2*a11.d));
    ADD2(a5.d,aa5.d,c1,zero.d,c2,cc2,t1,t2)
    MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
    ADD2(a3.d,aa3.d,c1,cc1,c2,cc2,t1,t2)
    MUL2(z2,zz2,c2,cc2,c1,cc1,t1,t2,t3,t4,t5,t6,t7,t8)
    MUL2(z ,zz ,c1,cc1,c2,cc2,t1,t2,t3,t4,t5,t6,t7,t8)
    ADD2(z ,zz ,c2,cc2,c1,cc1,t1,t2)
    ADD2(fi ,ffi,c1,cc1,c2,cc2,t1,t2)
    MUL2(fi ,ffi,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8)
    SUB2(one.d,zero.d,c3,cc3,c1,cc1,t1,t2)

    if (n) {
      /* -cot */
      DIV2(c1,cc1,c2,cc2,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
       if ((y=c3+(cc3-u28.d*c3))==c3+(cc3+u28.d*c3))  return (-sy*y);
    } else {
      /* tan */
      DIV2(c2,cc2,c1,cc1,c3,cc3,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10)
      if ((y=c3+(cc3-u27.d*c3))==c3+(cc3+u27.d*c3))  return (sy*y);
    }
    return tanMp(x);
  }

};

/************************************************************************/
/*  Routine compute sin(x) for  2^-26 < |x|< 0.25 by  Taylor with more   */
/* precision  and if still doesn't accurate enough by mpsin   or dubsin */
/************************************************************************/

static double slow(double x) {
static const double th2_36 = 206158430208.0;   /*    1.5*2**37   */
 double y,x1,x2,xx,r,t,res,cor,w[2];
 x1=(x+th2_36)-th2_36;
 y = aa.x*x1*x1*x1;
 r=x+y;
 x2=x-x1;
 xx=x*x;
 t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + bb.x)*xx + 3.0*aa.x*x1*x2)*x +aa.x*x2*x2*x2;
 t=((x-r)+y)+t;
 res=r+t;
 cor = (r-res)+t;
 if (res == res + 1.0007*cor) return res;
 else {
   dosincos::__dubsin(ABS(x),0,w);
   if (w[0] == w[0]+1.000000001*w[1]) return (x>0)?w[0]:-w[0];
   else return (x>0)?mpa::__mpsin(x,0):-mpa::__mpsin(-x,0);
 }
}
/*******************************************************************************/
/* Routine compute sin(x) for   0.25<|x|< 0.855469 by  sincos.tbl   and Taylor */
/* and if result still doesn't accurate enough by mpsin   or dubsin            */
/*******************************************************************************/

static double slow1(double x) {
  mynumber u;
  double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,c1,c2,xx,cor,res;
  static const double t22 = 6291456.0;
  int4 k;
  y=ABS(x);
  u.x=big.x+y;
  y=y-(u.x-big.x);
  xx=y*y;
  s = y*xx*(sn3 +xx*sn5);
  c = xx*(cs2 +xx*(cs4 + xx*cs6));
  k=u.i[LOW_HALF]<<2;
  sn=sincos.x[k];          /* Data          */
  ssn=sincos.x[k+1];       /*  from         */
  cs=sincos.x[k+2];        /*   tables      */
  ccs=sincos.x[k+3];       /*    sincos.tbl */
  y1 = (y+t22)-t22;
  y2 = y - y1;
  c1 = (cs+t22)-t22;
  c2=(cs-c1)+ccs;
  cor=(ssn+s*ccs+cs*s+c2*y+c1*y2)-sn*c;
  y=sn+c1*y1;
  cor = cor+((sn-y)+c1*y1);
  res=y+cor;
  cor=(y-res)+cor;
  if (res == res+1.0005*cor) return (x>0)?res:-res;
  else {
    dosincos::__dubsin(ABS(x),0,w);
    if (w[0] == w[0]+1.000000005*w[1]) return (x>0)?w[0]:-w[0];
    else return (x>0)?mpa::__mpsin(x,0):-mpa::__mpsin(-x,0);
  }
}
/**************************************************************************/
/*  Routine compute sin(x) for   0.855469  <|x|<2.426265  by  sincos.tbl  */
/* and if result still doesn't accurate enough by mpsin   or dubsin       */
/**************************************************************************/
static double slow2(double x) {
  mynumber u;
  double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,e1,e2,xx,cor,res,del;
  static const double t22 = 6291456.0;
  int4 k;
  y=ABS(x);
  y = hp0.x-y;
  if (y>=0) {
    u.x = big.x+y;
    y = y-(u.x-big.x);
    del = hp1.x;
  }
  else {
    u.x = big.x-y;
    y = -(y+(u.x-big.x));
    del = -hp1.x;
  }
  xx=y*y;
  s = y*xx*(sn3 +xx*sn5);
  c = y*del+xx*(cs2 +xx*(cs4 + xx*cs6));
  k=u.i[LOW_HALF]<<2;
  sn=sincos.x[k];
  ssn=sincos.x[k+1];
  cs=sincos.x[k+2];
  ccs=sincos.x[k+3];
  y1 = (y+t22)-t22;
  y2 = (y - y1)+del;
  e1 = (sn+t22)-t22;
  e2=(sn-e1)+ssn;
  cor=(ccs-cs*c-e1*y2-e2*y)-sn*s;
  y=cs-e1*y1;
  cor = cor+((cs-y)-e1*y1);
  res=y+cor;
  cor=(y-res)+cor;
  if (res == res+1.0005*cor) return (x>0)?res:-res;
  else {
    y=ABS(x)-hp0.x;
    y1=y-hp1.x;
    y2=(y-y1)-hp1.x;
    dosincos::__docos(y1,y2,w);
    if (w[0] == w[0]+1.000000005*w[1]) return (x>0)?w[0]:-w[0];
    else return (x>0)?mpa::__mpsin(x,0):-mpa::__mpsin(-x,0);
  }
}
/***************************************************************************/
/*  Routine compute sin(x+dx) (Double-Length number) where x is small enough*/
/* to use Taylor series around zero and   (x+dx)                            */
/* in first or third quarter of unit circle.Routine receive also            */
/* (right argument) the  original   value of x for computing error of      */
/* result.And if result not accurate enough routine calls mpsin1 or dubsin */
/***************************************************************************/

static double sloww(double x,double dx, double orig) {
  static const double th2_36 = 206158430208.0;   /*    1.5*2**37   */
  double y,x1,x2,xx,r,t,res,cor,w[2],a,da,xn;
  union {int4 i[2]; double x;} v;
  int4 n;
  x1=(x+th2_36)-th2_36;
  y = aa.x*x1*x1*x1;
  r=x+y;
  x2=(x-x1)+dx;
  xx=x*x;
  t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + bb.x)*xx + 3.0*aa.x*x1*x2)*x +aa.x*x2*x2*x2+dx;
  t=((x-r)+y)+t;
  res=r+t;
  cor = (r-res)+t;
  cor = (cor>0)? 1.0005*cor+ABS(orig)*3.1e-30 : 1.0005*cor-ABS(orig)*3.1e-30;
  if (res == res + cor) return res;
  else {
    (x>0)? dosincos::__dubsin(x,dx,w) : dosincos::__dubsin(-x,-dx,w);
    cor = (w[1]>0)? 1.000000001*w[1] + ABS(orig)*1.1e-30 : 1.000000001*w[1] - ABS(orig)*1.1e-30;
    if (w[0] == w[0]+cor) return (x>0)?w[0]:-w[0];
    else {
      t = (orig*hpinv.x + toint.x);
      xn = t - toint.x;
      v.x = t;
      y = (orig - xn*mp1.x) - xn*mp2.x;
      n =v.i[LOW_HALF]&3;
      da = xn*pp3.x;
      t=y-da;
      da = (y-t)-da;
      y = xn*pp4.x;
      a = t - y;
      da = ((t-a)-y)+da;
      if (n&2) {a=-a; da=-da;}
      (a>0)? dosincos::__dubsin(a,da,w) : dosincos::__dubsin(-a,-da,w);
      cor = (w[1]>0)? 1.000000001*w[1] + ABS(orig)*1.1e-40 : 1.000000001*w[1] - ABS(orig)*1.1e-40;
      if (w[0] == w[0]+cor) return (a>0)?w[0]:-w[0];
      else return mpa::__mpsin1(orig);
    }
  }
}
/***************************************************************************/
/*  Routine compute sin(x+dx)   (Double-Length number) where x in first or  */
/*  third quarter of unit circle.Routine receive also (right argument) the  */
/*  original   value of x for computing error of result.And if result not  */
/* accurate enough routine calls  mpsin1   or dubsin                       */
/***************************************************************************/

static double sloww1(double x, double dx, double orig) {
  mynumber u;
  double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,c1,c2,xx,cor,res;
  static const double t22 = 6291456.0;
  int4 k;
  y=ABS(x);
  u.x=big.x+y;
  y=y-(u.x-big.x);
  dx=(x>0)?dx:-dx;
  xx=y*y;
  s = y*xx*(sn3 +xx*sn5);
  c = xx*(cs2 +xx*(cs4 + xx*cs6));
  k=u.i[LOW_HALF]<<2;
  sn=sincos.x[k];
  ssn=sincos.x[k+1];
  cs=sincos.x[k+2];
  ccs=sincos.x[k+3];
  y1 = (y+t22)-t22;
  y2 = (y - y1)+dx;
  c1 = (cs+t22)-t22;
  c2=(cs-c1)+ccs;
  cor=(ssn+s*ccs+cs*s+c2*y+c1*y2-sn*y*dx)-sn*c;
  y=sn+c1*y1;
  cor = cor+((sn-y)+c1*y1);
  res=y+cor;
  cor=(y-res)+cor;
  cor = (cor>0)? 1.0005*cor+3.1e-30*ABS(orig) : 1.0005*cor-3.1e-30*ABS(orig);
  if (res == res + cor) return (x>0)?res:-res;
  else {
    dosincos::__dubsin(ABS(x),dx,w);
    cor = (w[1]>0)? 1.000000005*w[1]+1.1e-30*ABS(orig) : 1.000000005*w[1]-1.1e-30*ABS(orig);
    if (w[0] == w[0]+cor) return (x>0)?w[0]:-w[0];
  else  return mpa::__mpsin1(orig);
  }
}
/***************************************************************************/
/*  Routine compute sin(x+dx)   (Double-Length number) where x in second or */
/*  fourth quarter of unit circle.Routine receive also  the  original value */
/* and quarter(n= 1or 3)of x for computing error of result.And if result not*/
/* accurate enough routine calls  mpsin1   or dubsin                       */
/***************************************************************************/

static double sloww2(double x, double dx, double orig, int n) {
  mynumber u;
  double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,e1,e2,xx,cor,res;
  static const double t22 = 6291456.0;
  int4 k;
  y=ABS(x);
  u.x=big.x+y;
  y=y-(u.x-big.x);
  dx=(x>0)?dx:-dx;
  xx=y*y;
  s = y*xx*(sn3 +xx*sn5);
  c = y*dx+xx*(cs2 +xx*(cs4 + xx*cs6));
  k=u.i[LOW_HALF]<<2;
  sn=sincos.x[k];
  ssn=sincos.x[k+1];
  cs=sincos.x[k+2];
  ccs=sincos.x[k+3];

  y1 = (y+t22)-t22;
  y2 = (y - y1)+dx;
  e1 = (sn+t22)-t22;
  e2=(sn-e1)+ssn;
  cor=(ccs-cs*c-e1*y2-e2*y)-sn*s;
  y=cs-e1*y1;
  cor = cor+((cs-y)-e1*y1);
  res=y+cor;
  cor=(y-res)+cor;
  cor = (cor>0)? 1.0005*cor+3.1e-30*ABS(orig) : 1.0005*cor-3.1e-30*ABS(orig);
  if (res == res + cor) return (n&2)?-res:res;
  else {
    dosincos::__docos(ABS(x),dx,w);
    cor = (w[1]>0)? 1.000000005*w[1]+1.1e-30*ABS(orig) : 1.000000005*w[1]-1.1e-30*ABS(orig);
    if (w[0] == w[0]+cor) return (n&2)?-w[0]:w[0];
    else  return mpa::__mpsin1(orig);
  }
}
/***************************************************************************/
/*  Routine compute sin(x+dx) or cos(x+dx) (Double-Length number) where x   */
/* is small enough to use Taylor series around zero and   (x+dx)            */
/* in first or third quarter of unit circle.Routine receive also            */
/* (right argument) the  original   value of x for computing error of      */
/* result.And if result not accurate enough routine calls other routines    */
/***************************************************************************/

static double bsloww(double x,double dx, double orig,int n) {
  static const double th2_36 = 206158430208.0;   /*    1.5*2**37   */
  double y,x1,x2,xx,r,t,res,cor,w[2];
#if 0
  double a,da,xn;
  union {int4 i[2]; double x;} v;
#endif
  x1=(x+th2_36)-th2_36;
  y = aa.x*x1*x1*x1;
  r=x+y;
  x2=(x-x1)+dx;
  xx=x*x;
  t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + bb.x)*xx + 3.0*aa.x*x1*x2)*x +aa.x*x2*x2*x2+dx;
  t=((x-r)+y)+t;
  res=r+t;
  cor = (r-res)+t;
  cor = (cor>0)? 1.0005*cor+1.1e-24 : 1.0005*cor-1.1e-24;
  if (res == res + cor) return res;
  else {
    (x>0)? dosincos::__dubsin(x,dx,w) : dosincos::__dubsin(-x,-dx,w);
    cor = (w[1]>0)? 1.000000001*w[1] + 1.1e-24 : 1.000000001*w[1] - 1.1e-24;
    if (w[0] == w[0]+cor) return (x>0)?w[0]:-w[0];
    else return (n&1)?mpa::__mpcos1(orig):mpa::__mpsin1(orig);
  }
}

/***************************************************************************/
/*  Routine compute sin(x+dx)  or cos(x+dx) (Double-Length number) where x  */
/* in first or third quarter of unit circle.Routine receive also            */
/* (right argument) the original  value of x for computing error of result.*/
/* And if result not  accurate enough routine calls  other routines         */
/***************************************************************************/

static double bsloww1(double x, double dx, double orig,int n) {
mynumber u;
 double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,c1,c2,xx,cor,res;
 static const double t22 = 6291456.0;
 int4 k;
 y=ABS(x);
 u.x=big.x+y;
 y=y-(u.x-big.x);
 dx=(x>0)?dx:-dx;
 xx=y*y;
 s = y*xx*(sn3 +xx*sn5);
 c = xx*(cs2 +xx*(cs4 + xx*cs6));
 k=u.i[LOW_HALF]<<2;
 sn=sincos.x[k];
 ssn=sincos.x[k+1];
 cs=sincos.x[k+2];
 ccs=sincos.x[k+3];
 y1 = (y+t22)-t22;
 y2 = (y - y1)+dx;
 c1 = (cs+t22)-t22;
 c2=(cs-c1)+ccs;
 cor=(ssn+s*ccs+cs*s+c2*y+c1*y2-sn*y*dx)-sn*c;
 y=sn+c1*y1;
 cor = cor+((sn-y)+c1*y1);
 res=y+cor;
 cor=(y-res)+cor;
 cor = (cor>0)? 1.0005*cor+1.1e-24 : 1.0005*cor-1.1e-24;
 if (res == res + cor) return (x>0)?res:-res;
 else {
   dosincos::__dubsin(ABS(x),dx,w);
   cor = (w[1]>0)? 1.000000005*w[1]+1.1e-24: 1.000000005*w[1]-1.1e-24;
   if (w[0] == w[0]+cor) return (x>0)?w[0]:-w[0];
   else  return (n&1)?mpa::__mpcos1(orig):mpa::__mpsin1(orig);
 }
}

/***************************************************************************/
/*  Routine compute sin(x+dx)  or cos(x+dx) (Double-Length number) where x  */
/* in second or fourth quarter of unit circle.Routine receive also  the     */
/* original value and quarter(n= 1or 3)of x for computing error of result.  */
/* And if result not accurate enough routine calls  other routines          */
/***************************************************************************/

static double bsloww2(double x, double dx, double orig, int n) {
mynumber u;
 double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,e1,e2,xx,cor,res;
 static const double t22 = 6291456.0;
 int4 k;
 y=ABS(x);
 u.x=big.x+y;
 y=y-(u.x-big.x);
 dx=(x>0)?dx:-dx;
 xx=y*y;
 s = y*xx*(sn3 +xx*sn5);
 c = y*dx+xx*(cs2 +xx*(cs4 + xx*cs6));
 k=u.i[LOW_HALF]<<2;
 sn=sincos.x[k];
 ssn=sincos.x[k+1];
 cs=sincos.x[k+2];
 ccs=sincos.x[k+3];

 y1 = (y+t22)-t22;
 y2 = (y - y1)+dx;
 e1 = (sn+t22)-t22;
 e2=(sn-e1)+ssn;
 cor=(ccs-cs*c-e1*y2-e2*y)-sn*s;
 y=cs-e1*y1;
 cor = cor+((cs-y)-e1*y1);
 res=y+cor;
 cor=(y-res)+cor;
 cor = (cor>0)? 1.0005*cor+1.1e-24 : 1.0005*cor-1.1e-24;
 if (res == res + cor) return (n&2)?-res:res;
 else {
   dosincos::__docos(ABS(x),dx,w);
   cor = (w[1]>0)? 1.000000005*w[1]+1.1e-24 : 1.000000005*w[1]-1.1e-24;
   if (w[0] == w[0]+cor) return (n&2)?-w[0]:w[0];
   else  return (n&1)?mpa::__mpsin1(orig):mpa::__mpcos1(orig);
 }
}

/************************************************************************/
/*  Routine compute cos(x) for  2^-27 < |x|< 0.25 by  Taylor with more   */
/* precision  and if still doesn't accurate enough by mpcos   or docos  */
/************************************************************************/

static double cslow2(double x) {
  mynumber u;
  double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,e1,e2,xx,cor,res;
  static const double t22 = 6291456.0;
  int4 k;
  y=ABS(x);
  u.x = big.x+y;
  y = y-(u.x-big.x);
  xx=y*y;
  s = y*xx*(sn3 +xx*sn5);
  c = xx*(cs2 +xx*(cs4 + xx*cs6));
  k=u.i[LOW_HALF]<<2;
  sn=sincos.x[k];
  ssn=sincos.x[k+1];
  cs=sincos.x[k+2];
  ccs=sincos.x[k+3];
  y1 = (y+t22)-t22;
  y2 = y - y1;
  e1 = (sn+t22)-t22;
  e2=(sn-e1)+ssn;
  cor=(ccs-cs*c-e1*y2-e2*y)-sn*s;
  y=cs-e1*y1;
  cor = cor+((cs-y)-e1*y1);
  res=y+cor;
  cor=(y-res)+cor;
  if (res == res+1.0005*cor)
    return res;
  else {
    y=ABS(x);
    dosincos::__docos(y,0,w);
    if (w[0] == w[0]+1.000000005*w[1]) return w[0];
    else return mpa::__mpcos(x,0);
  }
}

/***************************************************************************/
/*  Routine compute cos(x+dx) (Double-Length number) where x is small enough*/
/* to use Taylor series around zero and   (x+dx) .Routine receive also      */
/* (right argument) the  original   value of x for computing error of      */
/* result.And if result not accurate enough routine calls other routines    */
/***************************************************************************/


static double csloww(double x,double dx, double orig) {
  static const double th2_36 = 206158430208.0;   /*    1.5*2**37   */
  double y,x1,x2,xx,r,t,res,cor,w[2],a,da,xn;
  union {int4 i[2]; double x;} v;
  int4 n;
  x1=(x+th2_36)-th2_36;
  y = aa.x*x1*x1*x1;
  r=x+y;
  x2=(x-x1)+dx;
  xx=x*x;
    /* Taylor series */
  t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + bb.x)*xx + 3.0*aa.x*x1*x2)*x +aa.x*x2*x2*x2+dx;
  t=((x-r)+y)+t;
  res=r+t;
  cor = (r-res)+t;
  cor = (cor>0)? 1.0005*cor+ABS(orig)*3.1e-30 : 1.0005*cor-ABS(orig)*3.1e-30;
  if (res == res + cor) return res;
  else {
    (x>0)? dosincos::__dubsin(x,dx,w) : dosincos::__dubsin(-x,-dx,w);
    cor = (w[1]>0)? 1.000000001*w[1] + ABS(orig)*1.1e-30 : 1.000000001*w[1] - ABS(orig)*1.1e-30;
    if (w[0] == w[0]+cor) return (x>0)?w[0]:-w[0];
    else {
      t = (orig*hpinv.x + toint.x);
      xn = t - toint.x;
      v.x = t;
      y = (orig - xn*mp1.x) - xn*mp2.x;
      n =v.i[LOW_HALF]&3;
      da = xn*pp3.x;
      t=y-da;
      da = (y-t)-da;
      y = xn*pp4.x;
      a = t - y;
      da = ((t-a)-y)+da;
      if (n==1) {a=-a; da=-da;}
      (a>0)? dosincos::__dubsin(a,da,w) : dosincos::__dubsin(-a,-da,w);
      cor = (w[1]>0)? 1.000000001*w[1] + ABS(orig)*1.1e-40 : 1.000000001*w[1] - ABS(orig)*1.1e-40;
      if (w[0] == w[0]+cor) return (a>0)?w[0]:-w[0];
      else return mpa::__mpcos1(orig);
    }
  }
}

/***************************************************************************/
/*  Routine compute sin(x+dx)   (Double-Length number) where x in first or  */
/*  third quarter of unit circle.Routine receive also (right argument) the  */
/*  original   value of x for computing error of result.And if result not  */
/* accurate enough routine calls  other routines                            */
/***************************************************************************/

static double csloww1(double x, double dx, double orig) {
  mynumber u;
  double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,c1,c2,xx,cor,res;
  static const double t22 = 6291456.0;
  int4 k;
  y=ABS(x);
  u.x=big.x+y;
  y=y-(u.x-big.x);
  dx=(x>0)?dx:-dx;
  xx=y*y;
  s = y*xx*(sn3 +xx*sn5);
  c = xx*(cs2 +xx*(cs4 + xx*cs6));
  k=u.i[LOW_HALF]<<2;
  sn=sincos.x[k];
  ssn=sincos.x[k+1];
  cs=sincos.x[k+2];
  ccs=sincos.x[k+3];
  y1 = (y+t22)-t22;
  y2 = (y - y1)+dx;
  c1 = (cs+t22)-t22;
  c2=(cs-c1)+ccs;
  cor=(ssn+s*ccs+cs*s+c2*y+c1*y2-sn*y*dx)-sn*c;
  y=sn+c1*y1;
  cor = cor+((sn-y)+c1*y1);
  res=y+cor;
  cor=(y-res)+cor;
  cor = (cor>0)? 1.0005*cor+3.1e-30*ABS(orig) : 1.0005*cor-3.1e-30*ABS(orig);
  if (res == res + cor) return (x>0)?res:-res;
  else {
    dosincos::__dubsin(ABS(x),dx,w);
    cor = (w[1]>0)? 1.000000005*w[1]+1.1e-30*ABS(orig) : 1.000000005*w[1]-1.1e-30*ABS(orig);
    if (w[0] == w[0]+cor) return (x>0)?w[0]:-w[0];
    else  return mpa::__mpcos1(orig);
  }
}


/***************************************************************************/
/*  Routine compute sin(x+dx)   (Double-Length number) where x in second or */
/*  fourth quarter of unit circle.Routine receive also  the  original value */
/* and quarter(n= 1or 3)of x for computing error of result.And if result not*/
/* accurate enough routine calls  other routines                            */
/***************************************************************************/

static double csloww2(double x, double dx, double orig, int n) {
  mynumber u;
  double sn,ssn,cs,ccs,s,c,w[2],y,y1,y2,e1,e2,xx,cor,res;
  static const double t22 = 6291456.0;
  int4 k;
  y=ABS(x);
  u.x=big.x+y;
  y=y-(u.x-big.x);
  dx=(x>0)?dx:-dx;
  xx=y*y;
  s = y*xx*(sn3 +xx*sn5);
  c = y*dx+xx*(cs2 +xx*(cs4 + xx*cs6));
  k=u.i[LOW_HALF]<<2;
  sn=sincos.x[k];
  ssn=sincos.x[k+1];
  cs=sincos.x[k+2];
  ccs=sincos.x[k+3];

  y1 = (y+t22)-t22;
  y2 = (y - y1)+dx;
  e1 = (sn+t22)-t22;
  e2=(sn-e1)+ssn;
  cor=(ccs-cs*c-e1*y2-e2*y)-sn*s;
  y=cs-e1*y1;
  cor = cor+((cs-y)-e1*y1);
  res=y+cor;
  cor=(y-res)+cor;
  cor = (cor>0)? 1.0005*cor+3.1e-30*ABS(orig) : 1.0005*cor-3.1e-30*ABS(orig);
  if (res == res + cor) return (n)?-res:res;
  else {
    dosincos::__docos(ABS(x),dx,w);
    cor = (w[1]>0)? 1.000000005*w[1]+1.1e-30*ABS(orig) : 1.000000005*w[1]-1.1e-30*ABS(orig);
    if (w[0] == w[0]+cor) return (n)?-w[0]:w[0];
    else  return mpa::__mpcos1(orig);
  }
}

union ieee754_float {
  float f;

  /* This is the IEEE 754 single-precision format.  */
  struct { W32 mantissa:23, exponent:8, negative:1; } ieee;

  /* This format makes it easier to see if a NaN is a signalling NaN.  */
  struct { W32 mantissa:22, quiet_nan:1, exponent:8, negative:1; } ieee_nan;
};

#define IEEE754_FLOAT_BIAS	0x7f /* Added to exponent.  */


union ieee754_double {
  double d;

  /* This is the IEEE 754 double-precision format.  */
  struct {
    W32 mantissa1:32;
    W32 mantissa0:20, exponent:11, negative:1;
  } ieee;

  /* This format makes it easier to see if a NaN is a signalling NaN.  */
  struct {
    /* Together these comprise the mantissa.  */
    W32 mantissa1:32;
    W32 mantissa0:19, quiet_nan:1, exponent:11, negative:1;
  } ieee_nan;
};

#define IEEE754_DOUBLE_BIAS	0x3ff /* Added to exponent.  */

  namespace explog {

  static const volatile double TWO1023 = 8.988465674311579539e+307;
  static const volatile double TWOM1000 = 9.3326361850321887899e-302;
  /* These values are accurate to 52+12 bits when represented as
     a double.  */
  static const double exp2_accuratetable[512] = {
    0.707106781187802013759 /* 0x0.b504f333fb3f80007 */,
    0.708064712808760599040 /* 0x0.b543baa0f71b38000 */,
    0.709023942160304065938 /* 0x0.b58297d3a8d518002 */,
    0.709984470998547667624 /* 0x0.b5c18ad39b4ba0001 */,
    0.710946301084324217006 /* 0x0.b60093a85e8d30001 */,
    0.711909434180505784637 /* 0x0.b63fb25984e628005 */,
    0.712873872052760648733 /* 0x0.b67ee6eea3b5f8003 */,
    0.713839616467838999908 /* 0x0.b6be316f518c98001 */,
    0.714806669195984345523 /* 0x0.b6fd91e328d148007 */,
    0.715775032009894562898 /* 0x0.b73d0851c69e20002 */,
    0.716744706683768884058 /* 0x0.b77c94c2c9b3d0003 */,
    0.717715694995770148178 /* 0x0.b7bc373dd52eb0003 */,
    0.718687998724665488852 /* 0x0.b7fbefca8cd530004 */,
    0.719661619652575468291 /* 0x0.b83bbe70981da8001 */,
    0.720636559564428180758 /* 0x0.b87ba337a194b0006 */,
    0.721612820246623098989 /* 0x0.b8bb9e27556508004 */,
    0.722590403488338473025 /* 0x0.b8fbaf4762c798006 */,
    0.723569311081411870036 /* 0x0.b93bd69f7be1d0000 */,
    0.724549544820974333906 /* 0x0.b97c1437567828007 */,
    0.725531106502312561633 /* 0x0.b9bc6816a87ae8002 */,
    0.726513997924421062181 /* 0x0.b9fcd2452bee00000 */,
    0.727498220889519875430 /* 0x0.ba3d52ca9e6148002 */,
    0.728483777200401694265 /* 0x0.ba7de9aebe05c8003 */,
    0.729470668664712662563 /* 0x0.babe96f94e62a8002 */,
    0.730458897090379144517 /* 0x0.baff5ab2134df0004 */,
    0.731448464287988597833 /* 0x0.bb4034e0d38ab0000 */,
    0.732439372072965166897 /* 0x0.bb81258d5b2d60001 */,
    0.733431622260458326859 /* 0x0.bbc22cbf75fd28001 */,
    0.734425216668725511232 /* 0x0.bc034a7ef32c00001 */,
    0.735420157118880535324 /* 0x0.bc447ed3a50fe0005 */,
    0.736416445434497690674 /* 0x0.bc85c9c560b350001 */,
    0.737414083433310718618 /* 0x0.bcc72b5bf4b4e0000 */,
    0.738413072966152328496 /* 0x0.bd08a39f5417a8007 */,
    0.739413415848264365956 /* 0x0.bd4a32974abcd0002 */,
    0.740415113911250699637 /* 0x0.bd8bd84bb68300002 */,
    0.741418168994518067562 /* 0x0.bdcd94c47ddd30003 */,
    0.742422582936659858376 /* 0x0.be0f6809865968006 */,
    0.743428357577745613238 /* 0x0.be515222b72530003 */,
    0.744435494762383687126 /* 0x0.be935317fc6ba0002 */,
    0.745443996335090397492 /* 0x0.bed56af1423de8001 */,
    0.746453864145572798553 /* 0x0.bf1799b67a6248007 */,
    0.747465100043933849969 /* 0x0.bf59df6f970e70002 */,
    0.748477705883256683178 /* 0x0.bf9c3c248dbee8001 */,
    0.749491683518965001732 /* 0x0.bfdeafdd568308000 */,
    0.750507034813367890373 /* 0x0.c0213aa1f0fc38004 */,
    0.751523761622240105153 /* 0x0.c063dc7a559ca0003 */,
    0.752541865811731880422 /* 0x0.c0a6956e883ed8000 */,
    0.753561349247157341600 /* 0x0.c0e965868bd220006 */,
    0.754582213796583967110 /* 0x0.c12c4cca664cb8002 */,
    0.755604461332336940791 /* 0x0.c16f4b42225350006 */,
    0.756628093726406381068 /* 0x0.c1b260f5ca2c48002 */,
    0.757653112855631305506 /* 0x0.c1f58ded6d72d8001 */,
    0.758679520599333412360 /* 0x0.c238d2311e7d08001 */,
    0.759707318837184453227 /* 0x0.c27c2dc8f00368005 */,
    0.760736509456435783249 /* 0x0.c2bfa0bcfd1400000 */,
    0.761767094336480043995 /* 0x0.c3032b155818d0000 */,
    0.762799075372231349951 /* 0x0.c346ccda248cc0001 */,
    0.763832454453522768941 /* 0x0.c38a8613805488005 */,
    0.764867233473625618441 /* 0x0.c3ce56c98d1ca8005 */,
    0.765903414329434539816 /* 0x0.c4123f04708d80002 */,
    0.766940998920452976510 /* 0x0.c4563ecc532dc0001 */,
    0.767979989148100838946 /* 0x0.c49a56295f9f88006 */,
    0.769020386915772125040 /* 0x0.c4de8523c2b0a0001 */,
    0.770062194131770905170 /* 0x0.c522cbc3ae94e0003 */,
    0.771105412703856241146 /* 0x0.c5672a1154e6b8004 */,
    0.772150044545352520777 /* 0x0.c5aba014ed5f18003 */,
    0.773196091570364285606 /* 0x0.c5f02dd6b09288003 */,
    0.774243555696622731700 /* 0x0.c634d35edb1260003 */,
    0.775292438842697939641 /* 0x0.c67990b5aa5c18004 */,
    0.776342742931542928455 /* 0x0.c6be65e360bed8000 */,
    0.777394469888802008854 /* 0x0.c70352f0437f50004 */,
    0.778447621641124243320 /* 0x0.c74857e498fd00006 */,
    0.779502200118583399303 /* 0x0.c78d74c8ab5b60000 */,
    0.780558207255445668515 /* 0x0.c7d2a9a4c959f8000 */,
    0.781615644985491186966 /* 0x0.c817f681412f80002 */,
    0.782674515247667956808 /* 0x0.c85d5b6666c150006 */,
    0.783734819983036512536 /* 0x0.c8a2d85c904760003 */,
    0.784796561133562109454 /* 0x0.c8e86d6c14f850002 */,
    0.785859740645942328471 /* 0x0.c92e1a9d513ec8002 */,
    0.786924360469767103536 /* 0x0.c973dff8a4b390007 */,
    0.787990422552312885808 /* 0x0.c9b9bd866c6440007 */,
    0.789057928854407064640 /* 0x0.c9ffb34f1444b0001 */,
    0.790126881326406182996 /* 0x0.ca45c15afcc570001 */,
    0.791197281930050233534 /* 0x0.ca8be7b292db38000 */,
    0.792269132620954885659 /* 0x0.cad2265e3cbee8000 */,
    0.793342435380726906957 /* 0x0.cb187d667d3d38006 */,
    0.794417192158282659010 /* 0x0.cb5eecd3b33158006 */,
    0.795493404931386649540 /* 0x0.cba574ae5d2e80001 */,
    0.796571075671306805268 /* 0x0.cbec14fef2a348004 */,
    0.797650206352955137846 /* 0x0.cc32cdcdef0000000 */,
    0.798730798954342069432 /* 0x0.cc799f23d11d18000 */,
    0.799812855456121796232 /* 0x0.ccc089091abb28004 */,
    0.800896377841454287795 /* 0x0.cd078b86505c18003 */,
    0.801981368096190028208 /* 0x0.cd4ea6a3f97720007 */,
    0.803067828208752554378 /* 0x0.cd95da6aa057b8007 */,
    0.804155760170129796375 /* 0x0.cddd26e2d21b28001 */,
    0.805245165974338261710 /* 0x0.ce248c151f3330001 */,
    0.806336047619038653883 /* 0x0.ce6c0a0a1c1350001 */,
    0.807428407102107836855 /* 0x0.ceb3a0ca5d6be0006 */,
    0.808522246427078927792 /* 0x0.cefb505e7e2550007 */,
    0.809617567597010201484 /* 0x0.cf4318cf18a268002 */,
    0.810714372621179513182 /* 0x0.cf8afa24ce1c98004 */,
    0.811812663508675536069 /* 0x0.cfd2f4683f9810005 */,
    0.812912442272482604912 /* 0x0.d01b07a2126188003 */,
    0.814013710929394895825 /* 0x0.d06333daeff618001 */,
    0.815116471495287542325 /* 0x0.d0ab791b80d028006 */,
    0.816220725993571205593 /* 0x0.d0f3d76c75b330000 */,
    0.817326476447408967199 /* 0x0.d13c4ed67f1cf8000 */,
    0.818433724883006474832 /* 0x0.d184df6250e3b0001 */,
    0.819542473330909460055 /* 0x0.d1cd8918a3a328004 */,
    0.820652723822034690935 /* 0x0.d2164c02305fa0002 */,
    0.821764478391968422618 /* 0x0.d25f2827b53fb0005 */,
    0.822877739077315761840 /* 0x0.d2a81d91f188b8000 */,
    0.823992507918612782109 /* 0x0.d2f12c49a8d290005 */,
    0.825108786960634610365 /* 0x0.d33a5457a35e40003 */,
    0.826226578247117093869 /* 0x0.d38395c4a84848007 */,
    0.827345883828319528258 /* 0x0.d3ccf09985d958004 */,
    0.828466705754248966560 /* 0x0.d41664df0a1320005 */,
    0.829589046080638992111 /* 0x0.d45ff29e094330000 */,
    0.830712906863802391671 /* 0x0.d4a999df585a20005 */,
    0.831838290163696481037 /* 0x0.d4f35aabd04a60006 */,
    0.832965198041969556729 /* 0x0.d53d350c4be258002 */,
    0.834093632565442222342 /* 0x0.d5872909aba050007 */,
    0.835223595802037643865 /* 0x0.d5d136acd138e8006 */,
    0.836355089820669306292 /* 0x0.d61b5dfe9f7780004 */,
    0.837488116698010487424 /* 0x0.d6659f0801afa8005 */,
    0.838622678508982644113 /* 0x0.d6aff9d1e147d8004 */,
    0.839758777333464490056 /* 0x0.d6fa6e652d19e0000 */,
    0.840896415254110962690 /* 0x0.d744fccad70d00003 */,
    0.842035594355151628676 /* 0x0.d78fa50bd2c3b0000 */,
    0.843176316724478125433 /* 0x0.d7da673117e730007 */,
    0.844318584453106590905 /* 0x0.d8254343a19038003 */,
    0.845462399634695271912 /* 0x0.d870394c6dbf30003 */,
    0.846607764365415071965 /* 0x0.d8bb49547d37c0004 */,
    0.847754680744707056494 /* 0x0.d9067364d45608003 */,
    0.848903150873708822763 /* 0x0.d951b7867953b0006 */,
    0.850053176859071113491 /* 0x0.d99d15c2787a30006 */,
    0.851204760807439786431 /* 0x0.d9e88e21de11a0003 */,
    0.852357904828824897169 /* 0x0.da3420adba1508003 */,
    0.853512611037803181642 /* 0x0.da7fcd6f2184d8005 */,
    0.854668881550406100980 /* 0x0.dacb946f2afaf8000 */,
    0.855826718478671755185 /* 0x0.db1775b6e8ad48000 */,
    0.856986123964844970247 /* 0x0.db63714f8e0818006 */,
    0.858147100114499461478 /* 0x0.dbaf87422625b8000 */,
    0.859309649060962410524 /* 0x0.dbfbb797daa460002 */,
    0.860473772936213743282 /* 0x0.dc480259d3a710001 */,
    0.861639473872910177676 /* 0x0.dc9467913a0f48006 */,
    0.862806754008130227807 /* 0x0.dce0e7473b9b28003 */,
    0.863975615481124226159 /* 0x0.dd2d8185086c20006 */,
    0.865146060433749419813 /* 0x0.dd7a3653d38168005 */,
    0.866318091005120138881 /* 0x0.ddc705bcccd628000 */,
    0.867491709362415264210 /* 0x0.de13efc9434100004 */,
    0.868666917636779056818 /* 0x0.de60f4825df9b8005 */,
    0.869843717989716047624 /* 0x0.deae13f16599c0003 */,
    0.871022112578215268471 /* 0x0.defb4e1f9dc388002 */,
    0.872202103559697183859 /* 0x0.df48a3164a92f0001 */,
    0.873383693097737778847 /* 0x0.df9612deb6e878007 */,
    0.874566883362160263365 /* 0x0.dfe39d82348310001 */,
    0.875751676517234511901 /* 0x0.e031430a0f0688000 */,
    0.876938074732511840819 /* 0x0.e07f037f97e548001 */,
    0.878126080186539592654 /* 0x0.e0ccdeec2a75e0006 */,
    0.879315695055312818168 /* 0x0.e11ad5591f4078001 */,
    0.880506921518618312932 /* 0x0.e168e6cfd2f880004 */,
    0.881699761760385225541 /* 0x0.e1b71359a6df60003 */,
    0.882894217964411143207 /* 0x0.e2055afffc1178000 */,
    0.884090292325693805080 /* 0x0.e253bdcc3ffbb8001 */,
    0.885287987031581180559 /* 0x0.e2a23bc7d7a1d8002 */,
    0.886487304278189114386 /* 0x0.e2f0d4fc31ab80004 */,
    0.887688246263368285778 /* 0x0.e33f8972bea8a8005 */,
    0.888890815189881999840 /* 0x0.e38e5934f49010007 */,
    0.890095013257492739835 /* 0x0.e3dd444c460bd0007 */,
    0.891300842677948068626 /* 0x0.e42c4ac232f380000 */,
    0.892508305659222567226 /* 0x0.e47b6ca036f8b8005 */,
    0.893717404414979710310 /* 0x0.e4caa9efd40e58002 */,
    0.894928141160697743242 /* 0x0.e51a02ba8e2610007 */,
    0.896140518115016826430 /* 0x0.e5697709ecab90000 */,
    0.897354537501434679237 /* 0x0.e5b906e77c61d0006 */,
    0.898570201543732793877 /* 0x0.e608b25cca5ba8005 */,
    0.899787512470129891014 /* 0x0.e6587973688ce8002 */,
    0.901006472512270728537 /* 0x0.e6a85c34ecadb8000 */,
    0.902227083902570559127 /* 0x0.e6f85aaaed4f20006 */,
    0.903449348881299796343 /* 0x0.e74874df09a530003 */,
    0.904673269686823378091 /* 0x0.e798aadadecba0007 */,
    0.905898848559668845585 /* 0x0.e7e8fca80c3ee0001 */,
    0.907126087750156795426 /* 0x0.e8396a503c3fe0005 */,
    0.908354989505901100354 /* 0x0.e889f3dd1615b0002 */,
    0.909585556079328783087 /* 0x0.e8da9958465228007 */,
    0.910817789726044213523 /* 0x0.e92b5acb7d0578001 */,
    0.912051692703457872481 /* 0x0.e97c38406c3c30003 */,
    0.913287267274154990210 /* 0x0.e9cd31c0cbb370001 */,
    0.914524515702244578108 /* 0x0.ea1e475654d540000 */,
    0.915763440256158633982 /* 0x0.ea6f790ac5cc78001 */,
    0.917004043205012497909 /* 0x0.eac0c6e7dd8448007 */,
    0.918246326823137892807 /* 0x0.eb1230f760a428007 */,
    0.919490293387826285200 /* 0x0.eb63b7431714a8007 */,
    0.920735945178816406225 /* 0x0.ebb559d4cb6f30007 */,
    0.921983284479243714322 /* 0x0.ec0718b64c0940002 */,
    0.923232313574974705626 /* 0x0.ec58f3f16a3910002 */,
    0.924483034755387955725 /* 0x0.ecaaeb8ffb3168005 */,
    0.925735450311948926408 /* 0x0.ecfcff9bd67078000 */,
    0.926989562542820610982 /* 0x0.ed4f301edad1a0007 */,
    0.928245373740515189457 /* 0x0.eda17d22e0f9b0001 */,
    0.929502886213858126045 /* 0x0.edf3e6b1d37d40001 */,
    0.930762102264245716494 /* 0x0.ee466cd594c5c8005 */,
    0.932023024199046146183 /* 0x0.ee990f980dcdb0005 */,
    0.933285654329454095216 /* 0x0.eeebcf032bc470007 */,
    0.934549994971191289044 /* 0x0.ef3eab20e0d3c0001 */,
    0.935816048439005676599 /* 0x0.ef91a3fb1e1340004 */,
    0.937083817055075818404 /* 0x0.efe4b99bdcc618006 */,
    0.938353303143720007819 /* 0x0.f037ec0d1889b8000 */,
    0.939624509028518128972 /* 0x0.f08b3b58cc2bb8006 */,
    0.940897437041863904384 /* 0x0.f0dea788fc2a90000 */,
    0.942172089516254085427 /* 0x0.f13230a7ad21b8003 */,
    0.943448468787511540534 /* 0x0.f185d6bee754e0006 */,
    0.944726577195256100890 /* 0x0.f1d999d8b73478005 */,
    0.946006417082291717338 /* 0x0.f22d79ff2cb130000 */,
    0.947287990793413858827 /* 0x0.f281773c59ec48007 */,
    0.948571300678290207925 /* 0x0.f2d5919a566268001 */,
    0.949856349088629370320 /* 0x0.f329c9233bceb0001 */,
    0.951143138379053731954 /* 0x0.f37e1de1272068002 */,
    0.952431670908847949364 /* 0x0.f3d28fde3a6728006 */,
    0.953721949039916472305 /* 0x0.f4271f249a93f0001 */,
    0.955013975135367898520 /* 0x0.f47bcbbe6deab0001 */,
    0.956307751564417496418 /* 0x0.f4d095b5e16638004 */,
    0.957603280698967163097 /* 0x0.f5257d1524f590006 */,
    0.958900564911197350604 /* 0x0.f57a81e668d628000 */,
    0.960199606581278120057 /* 0x0.f5cfa433e60e50007 */,
    0.961500408088936442422 /* 0x0.f624e407d527a0007 */,
    0.962802971817578789903 /* 0x0.f67a416c72b760006 */,
    0.964107300155846558292 /* 0x0.f6cfbc6c011458004 */,
    0.965413395493874504368 /* 0x0.f7255510c439a8002 */,
    0.966721260225105960572 /* 0x0.f77b0b6503c5b8006 */,
    0.968030896745834645873 /* 0x0.f7d0df730a7940005 */,
    0.969342307458006424716 /* 0x0.f826d145294be8003 */,
    0.970655494764855020231 /* 0x0.f87ce0e5b29fd8000 */,
    0.971970461071268720958 /* 0x0.f8d30e5efaa8f0004 */,
    0.973287208789983648852 /* 0x0.f92959bb5e3c08001 */,
    0.974605740331924708124 /* 0x0.f97fc305383028004 */,
    0.975926058115625383329 /* 0x0.f9d64a46ebb9f8004 */,
    0.977248164559556209435 /* 0x0.fa2cef8adbfc68004 */,
    0.978572062087848637573 /* 0x0.fa83b2db7253d0007 */,
    0.979897753126343307191 /* 0x0.fada944319fda0005 */,
    0.981225240104636631254 /* 0x0.fb3193cc425870002 */,
    0.982554525455618277276 /* 0x0.fb88b1815e61d0003 */,
    0.983885611617111077747 /* 0x0.fbdfed6ce683e0007 */,
    0.985218501026348891812 /* 0x0.fc3747995282f8006 */,
    0.986553196127724962867 /* 0x0.fc8ec0112202a0005 */,
    0.987889699367056062238 /* 0x0.fce656ded63710002 */,
    0.989228013193998778636 /* 0x0.fd3e0c0cf48d50005 */,
    0.990568140061241164686 /* 0x0.fd95dfa605c7b0003 */,
    0.991910082424819927754 /* 0x0.fdedd1b4965710004 */,
    0.993253842749249660216 /* 0x0.fe45e2433bfea0000 */,
    0.994599423484053835071 /* 0x0.fe9e115c7c05f0005 */,
    0.995946827107488830167 /* 0x0.fef65f0afb4c28006 */,
    0.997296056085008264529 /* 0x0.ff4ecb59509cc8001 */,
    0.998647112892057764479 /* 0x0.ffa756521dbfd0007 */,
    1.000000000000000000000 /* 0x1.00000000000000000 */,
    1.001354719891689004659 /* 0x1.0058c86da14aa0005 */,
    1.002711275050312211844 /* 0x1.00b1afa5abead0003 */,
    1.004069667960743483835 /* 0x1.010ab5b2cc0660009 */,
    1.005429901112333324093 /* 0x1.0163da9fb2af30008 */,
    1.006791976999887428009 /* 0x1.01bd1e7716f6a0008 */,
    1.008155898118476168101 /* 0x1.02168143b03890006 */,
    1.009521666967782227439 /* 0x1.027003103ae320002 */,
    1.010889286051850133326 /* 0x1.02c9a3e7783030002 */,
    1.012258757875921233497 /* 0x1.032363d42aaa8000e */,
    1.013630084952214405194 /* 0x1.037d42e11c88d0000 */,
    1.015003269791313389451 /* 0x1.03d741191635a0001 */,
    1.016378314911229763267 /* 0x1.04315e86e84630008 */,
    1.017755222831652872635 /* 0x1.048b9b35652800002 */,
    1.019133996077934645224 /* 0x1.04e5f72f65827000b */,
    1.020514637175266248212 /* 0x1.0540727fc1cfa0006 */,
    1.021897148653734488385 /* 0x1.059b0d3157ebb0002 */,
    1.023281533050062419584 /* 0x1.05f5c74f0cfeb0002 */,
    1.024667792897328677539 /* 0x1.0650a0e3c22ee0003 */,
    1.026055930738840826806 /* 0x1.06ab99fa63e1b0008 */,
    1.027445949118511947550 /* 0x1.0706b29ddf2700009 */,
    1.028837850584049418178 /* 0x1.0761ead9253ab0009 */,
    1.030231637685799839262 /* 0x1.07bd42b72a3f80008 */,
    1.031627312979383592802 /* 0x1.0818ba42e824a000c */,
    1.033024879021186448496 /* 0x1.0874518759b0b0008 */,
    1.034424338374263729911 /* 0x1.08d0088f80ffa0006 */,
    1.035825693601787333992 /* 0x1.092bdf66604e30005 */,
    1.037228947273990842283 /* 0x1.0987d617019cd000a */,
    1.038634101961269928846 /* 0x1.09e3ecac6f199000f */,
    1.040041160239590700707 /* 0x1.0a402331b91270002 */,
    1.041450124688240164200 /* 0x1.0a9c79b1f37c3000b */,
    1.042860997889083929381 /* 0x1.0af8f038352160000 */,
    1.044273782427270314011 /* 0x1.0b5586cf986890006 */,
    1.045688480893644856116 /* 0x1.0bb23d833dfbf0006 */,
    1.047105095879385272564 /* 0x1.0c0f145e46e330007 */,
    1.048523629981608529302 /* 0x1.0c6c0b6bdaadc000f */,
    1.049944085800634585634 /* 0x1.0cc922b72470a000f */,
    1.051366465939483019223 /* 0x1.0d265a4b5238b0007 */,
    1.052790773004648849929 /* 0x1.0d83b23395e510002 */,
    1.054217009607077093512 /* 0x1.0de12a7b263970006 */,
    1.055645178360430591625 /* 0x1.0e3ec32d3cf680000 */,
    1.057075281882416506511 /* 0x1.0e9c7c55184f5000e */,
    1.058507322794714378170 /* 0x1.0efa55fdfad51000a */,
    1.059941303721639416236 /* 0x1.0f58503329fed0003 */,
    1.061377227289284297385 /* 0x1.0fb66affed37f0000 */,
    1.062815096132297298980 /* 0x1.1014a66f95540000c */,
    1.064254912884593951029 /* 0x1.1073028d725850007 */,
    1.065696680185205469411 /* 0x1.10d17f64d9ea2000b */,
    1.067140400676658718053 /* 0x1.11301d012586a0007 */,
    1.068586077004890055886 /* 0x1.118edb6db26ab0003 */,
    1.070033711820396415998 /* 0x1.11edbab5e2d6e000b */,
    1.071483307775789262099 /* 0x1.124cbae51b5ef0001 */,
    1.072934867526001312439 /* 0x1.12abdc06c3240000c */,
    1.074388393734249103080 /* 0x1.130b1e264a62e0005 */,
    1.075843889063253344684 /* 0x1.136a814f20ccd0003 */,
    1.077301356179926061823 /* 0x1.13ca058cbaaed000b */,
    1.078760797756675327056 /* 0x1.1429aaea9260e000e */,
    1.080222216468626150775 /* 0x1.148971742537c0009 */,
    1.081685614993597610617 /* 0x1.14e95934f37e8000b */,
    1.083150996013011013776 /* 0x1.1549623881762000d */,
    1.084618362213087383633 /* 0x1.15a98c8a58a6a000b */,
    1.086087716284427351384 /* 0x1.1609d8360768c0008 */,
    1.087559060917626885283 /* 0x1.166a45471c13f0008 */,
    1.089032398810997337465 /* 0x1.16cad3c92d7b50009 */,
    1.090507732647478578212 /* 0x1.172b83c7c18b5000f */,
    1.091985065182095926460 /* 0x1.178c554ead72a000c */,
    1.093464399073070136880 /* 0x1.17ed48695befe000c */,
    1.094945737045367906172 /* 0x1.184e5d23812500007 */,
    1.096429081816546080591 /* 0x1.18af9388c90e40005 */,
    1.097914436104650892651 /* 0x1.1910eba4e031a0001 */,
    1.099401802629782043408 /* 0x1.19726583755720003 */,
    1.100891184121537858001 /* 0x1.19d4013041b860007 */,
    1.102382583308144647940 /* 0x1.1a35beb6fd0cd0007 */,
    1.103876002922312915544 /* 0x1.1a979e2363fa10000 */,
    1.105371445702084232160 /* 0x1.1af99f8139025000e */,
    1.106868914387219016199 /* 0x1.1b5bc2dc408b9000e */,
    1.108368411723785085252 /* 0x1.1bbe084045eb30002 */,
    1.109869940458469095340 /* 0x1.1c206fb91524c000e */,
    1.111373503344554869449 /* 0x1.1c82f952817cc0001 */,
    1.112879103137133007859 /* 0x1.1ce5a51860344000f */,
    1.114386742595953938610 /* 0x1.1d4873168babf000e */,
    1.115896424484008608911 /* 0x1.1dab6358e1d4a000f */,
    1.117408151567338414664 /* 0x1.1e0e75eb43f9c000c */,
    1.118921926613465345265 /* 0x1.1e71aad995078000f */,
    1.120437752409564780022 /* 0x1.1ed5022fcd8600003 */,
    1.121955631720569668277 /* 0x1.1f387bf9cd88b0000 */,
    1.123475567332998359439 /* 0x1.1f9c18438cdec000a */,
    1.124997562033035469759 /* 0x1.1fffd71902f970002 */,
    1.126521618608448571713 /* 0x1.2063b88629079000e */,
    1.128047739853580200284 /* 0x1.20c7bc96ff72a0002 */,
    1.129575928566289189112 /* 0x1.212be3578a81e0006 */,
    1.131106187546149888259 /* 0x1.21902cd3d05f70007 */,
    1.132638519598779369743 /* 0x1.21f49917ddda5000c */,
    1.134172927531616359481 /* 0x1.2259282fc1c24000e */,
    1.135709414157753949251 /* 0x1.22bdda27911e90007 */,
    1.137247982292643566662 /* 0x1.2322af0b638e60007 */,
    1.138788634756517259562 /* 0x1.2387a6e755f270000 */,
    1.140331374372893558110 /* 0x1.23ecc1c788c890006 */,
    1.141876203969685699176 /* 0x1.2451ffb821639000c */,
    1.143423126377846266197 /* 0x1.24b760c5486dc0009 */,
    1.144972144431494420774 /* 0x1.251ce4fb2a0cc0005 */,
    1.146523260971646252006 /* 0x1.25828c65f9fb8000d */,
    1.148076478839068270690 /* 0x1.25e85711ebaeb0000 */,
    1.149631800883562204903 /* 0x1.264e450b3c8a30008 */,
    1.151189229953253789786 /* 0x1.26b4565e281a20003 */,
    1.152748768902654319399 /* 0x1.271a8b16f0f000002 */,
    1.154310420590433317050 /* 0x1.2780e341de2fc0001 */,
    1.155874187878668246681 /* 0x1.27e75eeb3abc90007 */,
    1.157440073633736243899 /* 0x1.284dfe1f5633e000a */,
    1.159008080725518974322 /* 0x1.28b4c0ea840d90001 */,
    1.160578212048386514965 /* 0x1.291ba75932ae60000 */,
    1.162150470417516290340 /* 0x1.2982b177796850008 */,
    1.163724858777502646494 /* 0x1.29e9df51fdd900001 */,
    1.165301379991388053320 /* 0x1.2a5130f50bf34000e */,
    1.166880036952526289469 /* 0x1.2ab8a66d10fdc0008 */,
    1.168460832550151540268 /* 0x1.2b203fc675b7a000a */,
    1.170043769683112966389 /* 0x1.2b87fd0dad7260008 */,
    1.171628851252754177681 /* 0x1.2befde4f2e3da000d */,
    1.173216080163546060084 /* 0x1.2c57e397719940002 */,
    1.174805459325657830448 /* 0x1.2cc00cf2f7491000c */,
    1.176396991650083379037 /* 0x1.2d285a6e3ff90000b */,
    1.177990680055698513602 /* 0x1.2d90cc15d4ff90005 */,
    1.179586527463262646306 /* 0x1.2df961f641c57000c */,
    1.181184536796979545103 /* 0x1.2e621c1c157cd000d */,
    1.182784710984701836994 /* 0x1.2ecafa93e35af0004 */,
    1.184387052960675701386 /* 0x1.2f33fd6a459cb0000 */,
    1.185991565661414393112 /* 0x1.2f9d24abd8fd1000e */,
    1.187598252026902612178 /* 0x1.300670653e083000a */,
    1.189207115003001469262 /* 0x1.306fe0a31bc040008 */,
    1.190818157535919796833 /* 0x1.30d9757219895000e */,
    1.192431382587621380206 /* 0x1.31432edef01a1000f */,
    1.194046793097208292195 /* 0x1.31ad0cf63f0630008 */,
    1.195664392040319823392 /* 0x1.32170fc4ce0db000c */,
    1.197284182375793593084 /* 0x1.32813757527750005 */,
    1.198906167074650808198 /* 0x1.32eb83ba8eef3000f */,
    1.200530349107333139048 /* 0x1.3355f4fb457e5000d */,
    1.202156731453099647353 /* 0x1.33c08b2641df9000c */,
    1.203785317090505513368 /* 0x1.342b46484f07b0005 */,
    1.205416109005122526928 /* 0x1.3496266e3fa270005 */,
    1.207049110184904572310 /* 0x1.35012ba4e8fa10000 */,
    1.208684323627194912036 /* 0x1.356c55f92aabb0004 */,
    1.210321752322854882437 /* 0x1.35d7a577dd33f0004 */,
    1.211961399276747286580 /* 0x1.36431a2de8748000d */,
    1.213603267492579629347 /* 0x1.36aeb4283309e000c */,
    1.215247359985374142610 /* 0x1.371a7373b00160000 */,
    1.216893679753690671322 /* 0x1.3786581d404e90000 */,
    1.218542229828181611183 /* 0x1.37f26231e82e4000c */,
    1.220193013225231215567 /* 0x1.385e91be9c2d20002 */,
    1.221846032973555429280 /* 0x1.38cae6d05e66f0000 */,
    1.223501292099485437962 /* 0x1.393761742e5830001 */,
    1.225158793636904830441 /* 0x1.39a401b713cb3000e */,
    1.226818540625497444577 /* 0x1.3a10c7a61ceae0007 */,
    1.228480536107136034131 /* 0x1.3a7db34e5a4a50003 */,
    1.230144783126481566885 /* 0x1.3aeac4bcdf8d60001 */,
    1.231811284734168454619 /* 0x1.3b57fbfec6e950008 */,
    1.233480043984379381835 /* 0x1.3bc559212e7a2000f */,
    1.235151063936380300149 /* 0x1.3c32dc3139f2a0004 */,
    1.236824347652524913647 /* 0x1.3ca0853c106ac000e */,
    1.238499898199571624970 /* 0x1.3d0e544eddd240003 */,
    1.240177718649636107175 /* 0x1.3d7c4976d3fcd0000 */,
    1.241857812073360767273 /* 0x1.3dea64c1231f70004 */,
    1.243540181554270152039 /* 0x1.3e58a63b099920005 */,
    1.245224830175077013244 /* 0x1.3ec70df1c4e46000e */,
    1.246911761022835740725 /* 0x1.3f359bf29741c000e */,
    1.248600977188942806639 /* 0x1.3fa4504ac7b800009 */,
    1.250292481770148400634 /* 0x1.40132b07a330d000a */,
    1.251986277866492969263 /* 0x1.40822c367a340000b */,
    1.253682368581898742876 /* 0x1.40f153e4a18e0000d */,
    1.255380757024939564249 /* 0x1.4160a21f73289000d */,
    1.257081446308726757662 /* 0x1.41d016f44deaa000c */,
    1.258784439550028944083 /* 0x1.423fb27094c090008 */,
    1.260489739869405489991 /* 0x1.42af74a1aec1c0006 */,
    1.262197350394008266193 /* 0x1.431f5d950a453000c */,
    1.263907274252603851764 /* 0x1.438f6d58176860004 */,
    1.265619514578811388761 /* 0x1.43ffa3f84b9eb000d */,
    1.267334074511444086425 /* 0x1.44700183221180008 */,
    1.269050957191869555296 /* 0x1.44e0860618b930006 */,
    1.270770165768063009230 /* 0x1.4551318eb4d20000e */,
    1.272491703389059036805 /* 0x1.45c2042a7cc26000b */,
    1.274215573211836316547 /* 0x1.4632fde6ffacd000d */,
    1.275941778396075143580 /* 0x1.46a41ed1cfac40001 */,
    1.277670322103555911043 /* 0x1.471566f8812ac0000 */,
    1.279401207505722393185 /* 0x1.4786d668b33260005 */,
    1.281134437771823675369 /* 0x1.47f86d3002637000a */,
    1.282870016078732078362 /* 0x1.486a2b5c13c00000e */,
    1.284607945607987078432 /* 0x1.48dc10fa916bd0004 */,
    1.286348229545787758022 /* 0x1.494e1e192aaa30007 */,
    1.288090871080605159846 /* 0x1.49c052c5913df000c */,
    1.289835873406902644341 /* 0x1.4a32af0d7d8090002 */,
    1.291583239722392528754 /* 0x1.4aa532feab5e10002 */,
    1.293332973229098792374 /* 0x1.4b17dea6db8010008 */,
    1.295085077135345708087 /* 0x1.4b8ab213d57d9000d */,
    1.296839554650994097442 /* 0x1.4bfdad53629e10003 */,
    1.298596408992440220988 /* 0x1.4c70d0735358a000d */,
    1.300355643380135983739 /* 0x1.4ce41b817c99e0001 */,
    1.302117261036232376282 /* 0x1.4d578e8bb52cb0003 */,
    1.303881265192249561154 /* 0x1.4dcb299fde2920008 */,
    1.305647659079073541490 /* 0x1.4e3eeccbd7f4c0003 */,
    1.307416445934474813521 /* 0x1.4eb2d81d8a86f000b */,
    1.309187629001237640529 /* 0x1.4f26eba2e35a5000e */,
    1.310961211525240921493 /* 0x1.4f9b2769d35090009 */,
    1.312737196755087820678 /* 0x1.500f8b804e4a30000 */,
    1.314515587949291131086 /* 0x1.508417f4530d00009 */,
    1.316296388365203462468 /* 0x1.50f8ccd3df1840003 */,
    1.318079601265708777911 /* 0x1.516daa2cf60020002 */,
    1.319865229921343141607 /* 0x1.51e2b00da3c2b0007 */,
    1.321653277603506371251 /* 0x1.5257de83f5512000d */,
    1.323443747588034513690 /* 0x1.52cd359dfc7d5000e */,
    1.325236643161341820781 /* 0x1.5342b569d6baa000f */,
    1.327031967602244177939 /* 0x1.53b85df59921b0000 */,
    1.328829724206201046165 /* 0x1.542e2f4f6b17e0006 */,
    1.330629916266568235675 /* 0x1.54a4298571b27000e */,
    1.332432547083447937938 /* 0x1.551a4ca5d97190009 */,
    1.334237619959296017340 /* 0x1.559098bed16bf0008 */,
    1.336045138203900251029 /* 0x1.56070dde90c800000 */,
    1.337855105129210686631 /* 0x1.567dac13510cd0009 */,
    1.339667524053662184301 /* 0x1.56f4736b52e2c000c */,
    1.341482398296830025383 /* 0x1.576b63f4d8333000f */,
    1.343299731186792467254 /* 0x1.57e27dbe2c40e0003 */,
    1.345119526053918823702 /* 0x1.5859c0d59cd37000f */,
    1.346941786233264881662 /* 0x1.58d12d497cd9a0005 */,
    1.348766515064854010261 /* 0x1.5948c32824b87000c */,
    1.350593715891792223641 /* 0x1.59c0827ff03890007 */,
    1.352423392064920459908 /* 0x1.5a386b5f43a3e0006 */,
    1.354255546937278120764 /* 0x1.5ab07dd485af1000c */,
    1.356090183865519494030 /* 0x1.5b28b9ee21085000f */,
    1.357927306213322804534 /* 0x1.5ba11fba8816e000b */,
    1.359766917346459269620 /* 0x1.5c19af482f8f2000f */,
    1.361609020638567812980 /* 0x1.5c9268a594cc00004 */,
    1.363453619463660171403 /* 0x1.5d0b4be135916000c */,
    1.365300717204201985683 /* 0x1.5d84590998eeb0005 */,
    1.367150317245710233754 /* 0x1.5dfd902d494e40001 */,
    1.369002422974674892971 /* 0x1.5e76f15ad22c40008 */,
    1.370857037789471544224 /* 0x1.5ef07ca0cc166000b */,
    1.372714165088220639199 /* 0x1.5f6a320dcf5280006 */,
    1.374573808273481745378 /* 0x1.5fe411b0790800009 */,
    1.376435970755022220096 /* 0x1.605e1b976e4b1000e */,
    1.378300655944092456600 /* 0x1.60d84fd155d15000e */,
    1.380167867259843417228 /* 0x1.6152ae6cdf0030003 */,
    1.382037608124419003675 /* 0x1.61cd3778bc879000d */,
    1.383909881963391264069 /* 0x1.6247eb03a4dc40009 */,
    1.385784692209972801544 /* 0x1.62c2c91c56d9b0002 */,
    1.387662042298923203992 /* 0x1.633dd1d1930ec0001 */,
    1.389541935670444372533 /* 0x1.63b90532200630004 */,
    1.391424375772021271329 /* 0x1.6434634ccc4cc0007 */,
    1.393309366052102982208 /* 0x1.64afec30677e90008 */,
    1.395196909966106124701 /* 0x1.652b9febc8e0f000d */,
    1.397087010973788290271 /* 0x1.65a77e8dcc7f10004 */,
    1.398979672539331309267 /* 0x1.66238825534170000 */,
    1.400874898129892187656 /* 0x1.669fbcc1415600008 */,
    1.402772691220124823310 /* 0x1.671c1c708328e000a */,
    1.404673055288671035301 /* 0x1.6798a7420988b000d */,
    1.406575993818903302975 /* 0x1.68155d44ca77a000f */,
    1.408481510297352468121 /* 0x1.68923e87bf70e000a */,
    1.410389608216942924956 /* 0x1.690f4b19e8f74000c */,
    1.412300291075172076232 /* 0x1.698c830a4c94c0008 */
  };
#define S (1.0/4503599627370496.0)  /* 2^-52 */
  static const float exp2_deltatable[512] = {
    11527*S,  -963*S,   884*S,  -781*S, -2363*S, -3441*S,   123*S,   526*S,
    -6*S,  1254*S, -1138*S,  1519*S,  1576*S,   -65*S,  1040*S,   793*S,
    -1662*S, -5063*S,  -387*S,   968*S,  -941*S,   984*S, -2856*S,  -545*S,
    495*S, -5246*S, -2109*S,  1281*S,  2075*S,   909*S, -1642*S,-78233*S,
    -31653*S,  -265*S,   130*S,   430*S,  2482*S,  -742*S,  1616*S, -2213*S,
    -519*S,    20*S, -3134*S,-13981*S,  1343*S, -1740*S,   247*S,  1679*S,
    -1097*S,  3131*S,   871*S, -1480*S,  1936*S, -1827*S, 17325*S,   528*S,
    -322*S,  1404*S,  -152*S, -1845*S,  -212*S,  2639*S,  -476*S,  2960*S,
    -962*S, -1012*S, -1231*S,  3030*S,  1659*S,  -486*S,  2154*S,  1728*S,
    -2793*S,   699*S, -1560*S, -2125*S,  2156*S,   142*S, -1888*S,  4426*S,
    -13443*S,  1970*S,   -50*S,  1771*S,-43399*S,  4979*S, -2448*S,  -370*S,
    1414*S,  1075*S,   232*S,   206*S,   873*S,  2141*S,  2970*S,  1279*S,
    -2331*S,   336*S, -2595*S,   753*S, -3384*S,  -616*S,    89*S,  -818*S,
    5755*S,  -241*S,  -528*S,  -661*S, -3777*S,  -354*S,   250*S,  3881*S,
    2632*S, -2131*S,  2565*S,  -316*S,  1746*S, -2541*S, -1324*S,   -50*S,
    2564*S,  -782*S,  1176*S,  6452*S, -1002*S,  1288*S,   336*S,  -185*S,
    3063*S,  3784*S,  2169*S,   686*S,   328*S,  -400*S,   312*S, -4517*S,
    -1457*S,  1046*S, -1530*S,  -685*S,  1328*S,-49815*S,  -895*S,  1063*S,
    -2091*S,  -672*S, -1710*S,  -665*S,  1545*S,  1819*S,-45265*S,  3548*S,
    -554*S,  -568*S,  4752*S, -1907*S,-13738*S,   675*S,  9611*S, -1115*S,
    -815*S,   408*S, -1281*S,  -937*S,-16376*S, -4772*S, -1440*S,   992*S,
    788*S, 10364*S, -1602*S,  -661*S, -1783*S,  -265*S,   -20*S, -3781*S,
    -861*S,  -345*S,  -994*S,  1364*S, -5339*S,  1620*S,  9390*S, -1066*S,
    -305*S,  -170*S,   175*S,  2461*S,  -490*S,  -769*S, -1450*S,  3315*S,
    2418*S,   -45*S,  -852*S, -1295*S,  -488*S,   -96*S,  1142*S, -2639*S,
    7905*S, -9306*S, -3859*S,   760*S,  1057*S, -1570*S,  3977*S,   209*S,
    -514*S,  7151*S,  1646*S,   627*S,   599*S,  -774*S, -1468*S,   633*S,
    -473*S,   851*S,  2406*S,   143*S,    74*S,  4260*S,  1177*S,  -913*S,
    2670*S, -3298*S, -1662*S,  -120*S, -3264*S, -2148*S,   410*S,  2078*S,
    -2098*S,  -926*S,  3580*S, -1289*S,  2450*S, -1158*S,   907*S,  -590*S,
    986*S,  1801*S,  1145*S, -1677*S,  3455*S,   956*S,   710*S,   144*S,
    153*S,  -255*S, -1898*S, 28102*S,  2748*S,  1194*S, -3009*S,  7076*S,
    0*S, -2720*S,   711*S,  1225*S, -3034*S,  -473*S,   378*S, -1046*S,
    962*S, -2006*S,  4647*S,  3206*S,  1769*S, -2665*S,  1254*S,  2025*S,
    -2430*S,  6193*S,  1224*S,  -856*S, -1592*S,  -325*S, -1521*S,  1827*S,
    -264*S,  2403*S, -1065*S,   967*S,  -681*S, -2106*S,  -474*S,  1333*S,
    -893*S,  2296*S,   592*S, -1220*S,  -326*S,   990*S,   139*S,   206*S,
    -779*S, -1683*S,  1238*S,  6098*S,   136*S,  1197*S,   790*S,  -107*S,
    -1004*S, -2449*S,   939*S,  5568*S,   156*S,  1812*S,  2792*S, -1094*S,
    -2677*S,  -251*S,  2297*S,   943*S, -1329*S,  2883*S,  -853*S, -2626*S,
    -105929*S, -6552*S,  1095*S, -1508*S,  1003*S,  5039*S, -2600*S,  -749*S,
    1790*S,   890*S,  2016*S, -1073*S,   624*S, -2084*S, -1536*S, -1330*S,
    358*S,  2444*S,  -179*S,-25759*S,  -243*S,  -552*S,  -124*S,  3766*S,
    1192*S, -1614*S,     6*S, -1227*S,   345*S,  -981*S,  -295*S, -1006*S,
    -995*S, -1195*S,   706*S,  2512*S, -1758*S,  -734*S, -6286*S,  -922*S,
    1530*S,  1542*S,  1223*S,    61*S,   -83*S,   522*S,116937*S,  -914*S,
    -418*S, -7339*S,   249*S,  -520*S,  -762*S,   426*S,  -505*S,  2664*S,
    -1093*S, -1035*S,  2130*S,  4878*S,  1982*S,  1551*S,  2304*S,   193*S,
    1532*S, -7268*S, 24357*S,   531*S,  2676*S, -1170*S,  1465*S, -1917*S,
    2143*S,  1466*S,    -7*S, -7300*S,  3297*S, -1197*S,  -289*S, -1548*S,
    26226*S,  4401*S,  4123*S, -1588*S,  4243*S,  4069*S, -1276*S, -2010*S,
    1407*S,  1478*S,   488*S, -2366*S, -2909*S, -2534*S, -1285*S,  7095*S,
    -645*S, -2089*S,  -944*S,   -40*S, -1363*S,  -833*S,   917*S,  1609*S,
    1286*S,  1677*S,  1613*S, -2295*S, -1248*S,    40*S,    26*S,  2038*S,
    698*S,  2675*S, -1755*S, -3522*S, -1614*S, -6111*S,   270*S,  1822*S,
    -234*S, -2844*S, -1201*S,  -830*S,  1193*S,  2354*S,    47*S,  1522*S,
    -78*S,  -640*S,  2425*S, -1596*S,  1563*S,  1169*S, -1006*S,   -83*S,
    2362*S, -3521*S,  -314*S,  1814*S, -1751*S,   305*S,  1715*S, -3741*S,
    7847*S,  1291*S,  1206*S,    36*S,  1397*S, -1419*S, -1194*S, -2014*S,
    1742*S,  -578*S,  -207*S,   875*S,  1539*S,  2826*S, -1165*S,  -909*S,
    1849*S,   927*S,  2018*S,  -981*S,  1637*S,  -463*S,   905*S,  6618*S,
    400*S,   630*S,  2614*S,   900*S,  2323*S, -1094*S, -1858*S,  -212*S,
    -2069*S,   747*S,  1845*S, -1450*S,   444*S,  -213*S,  -438*S,  1158*S,
    4738*S,  2497*S,  -370*S, -2016*S,  -518*S, -1160*S, -1510*S,   123*S
  };
  /* Maximum magnitude in above table: 116937 */
#undef S

  double __ieee754_exp2(double x) {
    static const double himark = (double) DBL_MAX_EXP;
    static const double lomark = (double) (DBL_MIN_EXP - DBL_MANT_DIG - 1);

    /* Check for usual case.  */
    if (isless (x, himark) && isgreaterequal (x, lomark)) {
      static const double THREEp42 = 13194139533312.0;
      int tval, unsafe;
      double rx, x22, result;
      union ieee754_double ex2_u, scale_u;
      //fenv_t oldenv;
      
      MXCSR mxcsr(x86_get_mxcsr());
      W32 oldmxcsr = mxcsr;
      mxcsr.fields.rc = MXCSR_ROUND_NEAREST;
      x86_set_mxcsr(mxcsr);

      /* 1. Argument reduction.
         Choose integers ex, -256 <= t < 256, and some real
         -1/1024 <= x1 <= 1024 so that
         x = ex + t/512 + x1.

         First, calculate rx = ex + t/512.  */
      rx = x + THREEp42;
      rx -= THREEp42;
      x -= rx;  /* Compute x=x1. */
      /* Compute tval = (ex*512 + t)+256.
         Now, t = (tval mod 512)-256 and ex=tval/512  [that's mod, NOT %; and
         /-round-to-nearest not the usual c integer /].  */
      tval = (int) (rx * 512.0 + 256.0);

      /* 2. Adjust for accurate table entry.
         Find e so that
         x = ex + t/512 + e + x2
         where -1e6 < e < 1e6, and
         (double)(2^(t/512+e))
         is accurate to one part in 2^-64.  */

      /* 'tval & 511' is the same as 'tval%512' except that it's always
         positive.
         Compute x = x2.  */
      x -= exp2_deltatable[tval & 511];

      /* 3. Compute ex2 = 2^(t/512+e+ex).  */
      ex2_u.d = exp2_accuratetable[tval & 511];
      tval >>= 9;
      unsafe = abs<int>(tval) >= -DBL_MIN_EXP - 1;
      ex2_u.ieee.exponent += tval >> unsafe;
      scale_u.d = 1.0;
      scale_u.ieee.exponent += tval - (tval >> unsafe);

      /* 4. Approximate 2^x2 - 1, using a fourth-degree polynomial,
         with maximum error in [-2^-10-2^-30,2^-10+2^-30]
         less than 10^-19.  */

      x22 = (((.0096181293647031180
               * x + .055504110254308625)
              * x + .240226506959100583)
             * x + .69314718055994495) * ex2_u.d;

      /* 5. Return (2^x2-1) * 2^(t/512+e+ex) + 2^(t/512+e+ex).  */

      x86_set_mxcsr(oldmxcsr);

      result = x22 * x + ex2_u.d;

      if (!unsafe)
        return result;
      else
        return result * scale_u.d;
    } else if (isless (x, himark)) {
      /* Exceptional cases:  */
      if (math::isinf(x))
        /* e^-inf == 0, with no error.  */
        return 0;
      else
        /* Underflow */
        return TWOM1000 * TWOM1000;
    } else {
      /* Return x, if x is a NaN or Inf; or overflow, otherwise.  */
      return TWO1023*x;
    }
  }
};

  /*******************************************************************/
  /* An ultimate sin routine. Given an IEEE double machine number x   */
  /* it computes the correctly rounded (to nearest) value of sin(x)  */
  /*******************************************************************/
  double sin(double x){
    double xx,res,t,cor,y,s,c,sn,ssn,cs,ccs,xn,a,da,db,eps,xn1,xn2;
#if 0
    double w[2];
#endif
    mynumber u,v;
    int4 k,m,n;
#if 0
    int4 nn;
#endif

    u.x = x;
    m = u.i[HIGH_HALF];
    k = 0x7fffffff&m;              /* no sign           */
    if (k < 0x3e500000)            /* if x->0 =>sin(x)=x */
      return x;
    /*---------------------------- 2^-26 < |x|< 0.25 ----------------------*/
    else  if (k < 0x3fd00000){
      xx = x*x;
      /*Taylor series */
      t = ((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + s1.x)*(xx*x);
      res = x+t;
      cor = (x-res)+t;
      return (res == res + 1.07*cor)? res : slow(x);
    }    /*  else  if (k < 0x3fd00000)    */
    /*---------------------------- 0.25<|x|< 0.855469---------------------- */
    else if (k < 0x3feb6000)  {
      u.x=(m>0)?big.x+x:big.x-x;
      y=(m>0)?x-(u.x-big.x):x+(u.x-big.x);
      xx=y*y;
      s = y + y*xx*(sn3 +xx*sn5);
      c = xx*(cs2 +xx*(cs4 + xx*cs6));
      k=u.i[LOW_HALF]<<2;
      sn=(m>0)?sincos.x[k]:-sincos.x[k];
      ssn=(m>0)?sincos.x[k+1]:-sincos.x[k+1];
      cs=sincos.x[k+2];
      ccs=sincos.x[k+3];
      cor=(ssn+s*ccs-sn*c)+cs*s;
      res=sn+cor;
      cor=(sn-res)+cor;
      return (res==res+1.025*cor)? res : slow1(x);
    }    /*   else  if (k < 0x3feb6000)    */

    /*----------------------- 0.855469  <|x|<2.426265  ----------------------*/
    else if (k <  0x400368fd ) {

      y = (m>0)? hp0.x-x:hp0.x+x;
      if (y>=0) {
        u.x = big.x+y;
        y = (y-(u.x-big.x))+hp1.x;
      }
      else {
        u.x = big.x-y;
        y = (-hp1.x) - (y+(u.x-big.x));
      }
      xx=y*y;
      s = y + y*xx*(sn3 +xx*sn5);
      c = xx*(cs2 +xx*(cs4 + xx*cs6));
      k=u.i[LOW_HALF]<<2;
      sn=sincos.x[k];
      ssn=sincos.x[k+1];
      cs=sincos.x[k+2];
      ccs=sincos.x[k+3];
      cor=(ccs-s*ssn-cs*c)-sn*s;
      res=cs+cor;
      cor=(cs-res)+cor;
      return (res==res+1.020*cor)? ((m>0)?res:-res) : slow2(x);
    } /*   else  if (k < 0x400368fd)    */

    /*-------------------------- 2.426265<|x|< 105414350 ----------------------*/
    else if (k < 0x419921FB ) {
      t = (x*hpinv.x + toint.x);
      xn = t - toint.x;
      v.x = t;
      y = (x - xn*mp1.x) - xn*mp2.x;
      n =v.i[LOW_HALF]&3;
      da = xn*mp3.x;
      a=y-da;
      da = (y-a)-da;
      eps = ABS(x)*1.2e-30;

      switch (n) { /* quarter of unit circle */
      case 0:
      case 2:
        xx = a*a;
        if (n) {a=-a;da=-da;}
        if (xx < 0.01588) {
          /*Taylor series */
          t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + s1.x)*a - 0.5*da)*xx+da;
          res = a+t;
          cor = (a-res)+t;
          cor = (cor>0)? 1.02*cor+eps : 1.02*cor -eps;
          return (res == res + cor)? res : sloww(a,da,x);
        }
        else  {
          if (a>0)
            {m=1;t=a;db=da;}
          else
            {m=0;t=-a;db=-da;}
          u.x=big.x+t;
          y=t-(u.x-big.x);
          xx=y*y;
          s = y + (db+y*xx*(sn3 +xx*sn5));
          c = y*db+xx*(cs2 +xx*(cs4 + xx*cs6));
          k=u.i[LOW_HALF]<<2;
          sn=sincos.x[k];
          ssn=sincos.x[k+1];
          cs=sincos.x[k+2];
          ccs=sincos.x[k+3];
          cor=(ssn+s*ccs-sn*c)+cs*s;
          res=sn+cor;
          cor=(sn-res)+cor;
          cor = (cor>0)? 1.035*cor+eps : 1.035*cor-eps;
          return (res==res+cor)? ((m)?res:-res) : sloww1(a,da,x);
        }
        break;

      case 1:
      case 3:
        if (a<0)
          {a=-a;da=-da;}
        u.x=big.x+a;
        y=a-(u.x-big.x)+da;
        xx=y*y;
        k=u.i[LOW_HALF]<<2;
        sn=sincos.x[k];
        ssn=sincos.x[k+1];
        cs=sincos.x[k+2];
        ccs=sincos.x[k+3];
        s = y + y*xx*(sn3 +xx*sn5);
        c = xx*(cs2 +xx*(cs4 + xx*cs6));
        cor=(ccs-s*ssn-cs*c)-sn*s;
        res=cs+cor;
        cor=(cs-res)+cor;
        cor = (cor>0)? 1.025*cor+eps : 1.025*cor-eps;
        return (res==res+cor)? ((n&2)?-res:res) : sloww2(a,da,x,n);

        break;

      }

    }    /*   else  if (k <  0x419921FB )    */

    /*---------------------105414350 <|x|< 281474976710656 --------------------*/
    else if (k < 0x42F00000 ) {
      t = (x*hpinv.x + toint.x);
      xn = t - toint.x;
      v.x = t;
      xn1 = (xn+8.0e22)-8.0e22;
      xn2 = xn - xn1;
      y = ((((x - xn1*mp1.x) - xn1*mp2.x)-xn2*mp1.x)-xn2*mp2.x);
      n =v.i[LOW_HALF]&3;
      da = xn1*pp3.x;
      t=y-da;
      da = (y-t)-da;
      da = (da - xn2*pp3.x) -xn*pp4.x;
      a = t+da;
      da = (t-a)+da;
      eps = 1.0e-24;

      switch (n) {
      case 0:
      case 2:
        xx = a*a;
        if (n) {a=-a;da=-da;}
        if (xx < 0.01588) {
          /* Taylor series */
          t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + s1.x)*a - 0.5*da)*xx+da;
          res = a+t;
          cor = (a-res)+t;
          cor = (cor>0)? 1.02*cor+eps : 1.02*cor -eps;
          return (res == res + cor)? res : bsloww(a,da,x,n);
        }
        else  {
          if (a>0) {m=1;t=a;db=da;}
          else {m=0;t=-a;db=-da;}
          u.x=big.x+t;
          y=t-(u.x-big.x);
          xx=y*y;
          s = y + (db+y*xx*(sn3 +xx*sn5));
          c = y*db+xx*(cs2 +xx*(cs4 + xx*cs6));
          k=u.i[LOW_HALF]<<2;
          sn=sincos.x[k];
          ssn=sincos.x[k+1];
          cs=sincos.x[k+2];
          ccs=sincos.x[k+3];
          cor=(ssn+s*ccs-sn*c)+cs*s;
          res=sn+cor;
          cor=(sn-res)+cor;
          cor = (cor>0)? 1.035*cor+eps : 1.035*cor-eps;
          return (res==res+cor)? ((m)?res:-res) : bsloww1(a,da,x,n);
        }
        break;

      case 1:
      case 3:
        if (a<0)
          {a=-a;da=-da;}
        u.x=big.x+a;
        y=a-(u.x-big.x)+da;
        xx=y*y;
        k=u.i[LOW_HALF]<<2;
        sn=sincos.x[k];
        ssn=sincos.x[k+1];
        cs=sincos.x[k+2];
        ccs=sincos.x[k+3];
        s = y + y*xx*(sn3 +xx*sn5);
        c = xx*(cs2 +xx*(cs4 + xx*cs6));
        cor=(ccs-s*ssn-cs*c)-sn*s;
        res=cs+cor;
        cor=(cs-res)+cor;
        cor = (cor>0)? 1.025*cor+eps : 1.025*cor-eps;
        return (res==res+cor)? ((n&2)?-res:res) : bsloww2(a,da,x,n);

        break;

      }

    }    /*   else  if (k <  0x42F00000 )   */

    /* -----------------281474976710656 <|x| <2^1024----------------------------*/
    else if (k < 0x7ff00000) {

      n = branred::__branred(x,&a,&da);
      switch (n) {
      case 0:
        if (a*a < 0.01588) return bsloww(a,da,x,n);
        else return bsloww1(a,da,x,n);
        break;
      case 2:
        if (a*a < 0.01588) return bsloww(-a,-da,x,n);
        else return bsloww1(-a,-da,x,n);
        break;

      case 1:
      case 3:
        return  bsloww2(a,da,x,n);
        break;
      }

    }    /*   else  if (k <  0x7ff00000 )    */

    /*--------------------- |x| > 2^1024 ----------------------------------*/
    else return x / x;
    return 0;         /* unreachable */
  }


  /*******************************************************************/
  /* An ultimate cos routine. Given an IEEE double machine number x   */
  /* it computes the correctly rounded (to nearest) value of cos(x)  */
  /*******************************************************************/

  double cos(double x)
  {
    double y,xx,res,t,cor,s,c,sn,ssn,cs,ccs,xn,a,da,db,eps,xn1,xn2;
    mynumber u,v;
    int4 k,m,n;

    u.x = x;
    m = u.i[HIGH_HALF];
    k = 0x7fffffff&m;

    if (k < 0x3e400000 ) return 1.0; /* |x|<2^-27 => cos(x)=1 */

    else if (k < 0x3feb6000 ) {/* 2^-27 < |x| < 0.855469 */
      y=ABS(x);
      u.x = big.x+y;
      y = y-(u.x-big.x);
      xx=y*y;
      s = y + y*xx*(sn3 +xx*sn5);
      c = xx*(cs2 +xx*(cs4 + xx*cs6));
      k=u.i[LOW_HALF]<<2;
      sn=sincos.x[k];
      ssn=sincos.x[k+1];
      cs=sincos.x[k+2];
      ccs=sincos.x[k+3];
      cor=(ccs-s*ssn-cs*c)-sn*s;
      res=cs+cor;
      cor=(cs-res)+cor;
      return (res==res+1.020*cor)? res : cslow2(x);

    }    /*   else  if (k < 0x3feb6000)    */

    else if (k <  0x400368fd ) {/* 0.855469  <|x|<2.426265  */;
    y=hp0.x-ABS(x);
    a=y+hp1.x;
    da=(y-a)+hp1.x;
    xx=a*a;
    if (xx < 0.01588) {
      t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + s1.x)*a - 0.5*da)*xx+da;
      res = a+t;
      cor = (a-res)+t;
      cor = (cor>0)? 1.02*cor+1.0e-31 : 1.02*cor -1.0e-31;
      return (res == res + cor)? res : csloww(a,da,x);
    }
    else  {
      if (a>0) {m=1;t=a;db=da;}
      else {m=0;t=-a;db=-da;}
      u.x=big.x+t;
      y=t-(u.x-big.x);
      xx=y*y;
      s = y + (db+y*xx*(sn3 +xx*sn5));
      c = y*db+xx*(cs2 +xx*(cs4 + xx*cs6));
      k=u.i[LOW_HALF]<<2;
      sn=sincos.x[k];
      ssn=sincos.x[k+1];
      cs=sincos.x[k+2];
      ccs=sincos.x[k+3];
      cor=(ssn+s*ccs-sn*c)+cs*s;
      res=sn+cor;
      cor=(sn-res)+cor;
      cor = (cor>0)? 1.035*cor+1.0e-31 : 1.035*cor-1.0e-31;
      return (res==res+cor)? ((m)?res:-res) : csloww1(a,da,x);
    }

    }    /*   else  if (k < 0x400368fd)    */


    else if (k < 0x419921FB ) {/* 2.426265<|x|< 105414350 */
      t = (x*hpinv.x + toint.x);
      xn = t - toint.x;
      v.x = t;
      y = (x - xn*mp1.x) - xn*mp2.x;
      n =v.i[LOW_HALF]&3;
      da = xn*mp3.x;
      a=y-da;
      da = (y-a)-da;
      eps = ABS(x)*1.2e-30;

      switch (n) {
      case 1:
      case 3:
        xx = a*a;
        if (n == 1) {a=-a;da=-da;}
        if (xx < 0.01588) {
          t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + s1.x)*a - 0.5*da)*xx+da;
          res = a+t;
          cor = (a-res)+t;
          cor = (cor>0)? 1.02*cor+eps : 1.02*cor -eps;
          return (res == res + cor)? res : csloww(a,da,x);
        }
        else  {
          if (a>0) {m=1;t=a;db=da;}
          else {m=0;t=-a;db=-da;}
          u.x=big.x+t;
          y=t-(u.x-big.x);
          xx=y*y;
          s = y + (db+y*xx*(sn3 +xx*sn5));
          c = y*db+xx*(cs2 +xx*(cs4 + xx*cs6));
          k=u.i[LOW_HALF]<<2;
          sn=sincos.x[k];
          ssn=sincos.x[k+1];
          cs=sincos.x[k+2];
          ccs=sincos.x[k+3];
          cor=(ssn+s*ccs-sn*c)+cs*s;
          res=sn+cor;
          cor=(sn-res)+cor;
          cor = (cor>0)? 1.035*cor+eps : 1.035*cor-eps;
          return (res==res+cor)? ((m)?res:-res) : csloww1(a,da,x);
        }
        break;

      case 0:
      case 2:
        if (a<0) {a=-a;da=-da;}
        u.x=big.x+a;
        y=a-(u.x-big.x)+da;
        xx=y*y;
        k=u.i[LOW_HALF]<<2;
        sn=sincos.x[k];
        ssn=sincos.x[k+1];
        cs=sincos.x[k+2];
        ccs=sincos.x[k+3];
        s = y + y*xx*(sn3 +xx*sn5);
        c = xx*(cs2 +xx*(cs4 + xx*cs6));
        cor=(ccs-s*ssn-cs*c)-sn*s;
        res=cs+cor;
        cor=(cs-res)+cor;
        cor = (cor>0)? 1.025*cor+eps : 1.025*cor-eps;
        return (res==res+cor)? ((n)?-res:res) : csloww2(a,da,x,n);

        break;

      }

    }    /*   else  if (k <  0x419921FB )    */


    else if (k < 0x42F00000 ) {
      t = (x*hpinv.x + toint.x);
      xn = t - toint.x;
      v.x = t;
      xn1 = (xn+8.0e22)-8.0e22;
      xn2 = xn - xn1;
      y = ((((x - xn1*mp1.x) - xn1*mp2.x)-xn2*mp1.x)-xn2*mp2.x);
      n =v.i[LOW_HALF]&3;
      da = xn1*pp3.x;
      t=y-da;
      da = (y-t)-da;
      da = (da - xn2*pp3.x) -xn*pp4.x;
      a = t+da;
      da = (t-a)+da;
      eps = 1.0e-24;

      switch (n) {
      case 1:
      case 3:
        xx = a*a;
        if (n==1) {a=-a;da=-da;}
        if (xx < 0.01588) {
          t = (((((s5.x*xx + s4.x)*xx + s3.x)*xx + s2.x)*xx + s1.x)*a - 0.5*da)*xx+da;
          res = a+t;
          cor = (a-res)+t;
          cor = (cor>0)? 1.02*cor+eps : 1.02*cor -eps;
          return (res == res + cor)? res : bsloww(a,da,x,n);
        }
        else  {
          if (a>0) {m=1;t=a;db=da;}
          else {m=0;t=-a;db=-da;}
          u.x=big.x+t;
          y=t-(u.x-big.x);
          xx=y*y;
          s = y + (db+y*xx*(sn3 +xx*sn5));
          c = y*db+xx*(cs2 +xx*(cs4 + xx*cs6));
          k=u.i[LOW_HALF]<<2;
          sn=sincos.x[k];
          ssn=sincos.x[k+1];
          cs=sincos.x[k+2];
          ccs=sincos.x[k+3];
          cor=(ssn+s*ccs-sn*c)+cs*s;
          res=sn+cor;
          cor=(sn-res)+cor;
          cor = (cor>0)? 1.035*cor+eps : 1.035*cor-eps;
          return (res==res+cor)? ((m)?res:-res) : bsloww1(a,da,x,n);
        }
        break;

      case 0:
      case 2:
        if (a<0) {a=-a;da=-da;}
        u.x=big.x+a;
        y=a-(u.x-big.x)+da;
        xx=y*y;
        k=u.i[LOW_HALF]<<2;
        sn=sincos.x[k];
        ssn=sincos.x[k+1];
        cs=sincos.x[k+2];
        ccs=sincos.x[k+3];
        s = y + y*xx*(sn3 +xx*sn5);
        c = xx*(cs2 +xx*(cs4 + xx*cs6));
        cor=(ccs-s*ssn-cs*c)-sn*s;
        res=cs+cor;
        cor=(cs-res)+cor;
        cor = (cor>0)? 1.025*cor+eps : 1.025*cor-eps;
        return (res==res+cor)? ((n)?-res:res) : bsloww2(a,da,x,n);
        break;

      }

    }    /*   else  if (k <  0x42F00000 )    */

    else if (k < 0x7ff00000) {/* 281474976710656 <|x| <2^1024 */

      n = branred::__branred(x,&a,&da);
      switch (n) {
      case 1:
        if (a*a < 0.01588) return bsloww(-a,-da,x,n);
        else return bsloww1(-a,-da,x,n);
        break;
      case 3:
        if (a*a < 0.01588) return bsloww(a,da,x,n);
        else return bsloww1(a,da,x,n);
        break;

      case 0:
      case 2:
        return  bsloww2(a,da,x,n);
        break;
      }

    }    /*   else  if (k <  0x7ff00000 )    */

    else return x / x; /* |x| > 2^1024 */
    return 0;
  }

  double tan(double x) {
    return mpa::tan(x);
  }

  //
  // from glibc/sysdeps/ieee754/dbl-64/s_round.c:
  //

  static const double huge = 1.0e+300;
  static const double tiny = 1.0e-300;

  double round(double x) {
    W32s i0, j0;
    W32 i1;

    W64orDouble u;
    u.d = x;
    i0 = u.hilo.hi;
    i1 = u.hilo.lo;

    j0 = ((i0 >> 20) & 0x7ff) - 0x3ff;
    if (j0 < 20) {
      if (j0 < 0) {
        if (huge + x > 0.0) {
          i0 &= 0x80000000;
          if (j0 == -1)
            i0 |= 0x3ff00000;
          i1 = 0;
        }
      } else {
        W32 i = 0x000fffff >> j0;
        if (((i0 & i) | i1) == 0)
          /* X is integral.  */
          return x;
        if (huge + x > 0.0) {
          /* Raise inexact if x != 0.  */
          i0 += 0x00080000 >> j0;
          i0 &= ~i;
          i1 = 0;
        }
      }
    } else if (j0 > 51) {
      if (j0 == 0x400)
        /* Inf or NaN.  */
        return x + x;
      else
        return x;
    } else {
      W32 i = 0xffffffff >> (j0 - 20);
      if ((i1 & i) == 0)
        /* X is integral.  */
        return x;

      if (huge + x > 0.0) {
        /* Raise inexact if x != 0.  */
        W32 j = i1 + (1 << (51 - j0));
        if (j < i1)
          i0 += 1;
        i1 = j;
      }
      i1 &= ~i;
    }

    u.hilo.hi = i0;
    u.hilo.lo = i1;
    return u.d;
  }

  double floor(double x) {
    W32s i0,i1,j0;
    W32 i,j;

    W64orDouble u;
    u.d = x;
    i0 = u.hilo.hi;
    i1 = u.hilo.lo;

    j0 = ((i0>>20)&0x7ff)-0x3ff;
    if(j0<20) {
      if(j0<0) { 	/* raise inexact if x != 0 */
        if(huge+x>0.0) {/* return 0*sign(x) if |x|<1 */
          if(i0>=0) {i0=i1=0;}
          else if(((i0&0x7fffffff)|i1)!=0)
            { i0=0xbff00000;i1=0;}
        }
      } else {
        i = (0x000fffff)>>j0;
        if(((i0&i)|i1)==0) return x; /* x is integral */
        if(huge+x>0.0) {	/* raise inexact flag */
          if(i0<0) i0 += (0x00100000)>>j0;
          i0 &= (~i); i1=0;
        }
      }
    } else if (j0>51) {
      if(j0==0x400) return x+x;	/* inf or NaN */
      else return x;		/* x is integral */
    } else {
      i = ((W32)(0xffffffff))>>(j0-20);
      if((i1&i)==0) return x;	/* x is integral */
      if(huge+x>0.0) { 		/* raise inexact flag */
        if(i0<0) {
          if(j0==20) i0+=1;
          else {
            j = i1+(1<<(52-j0));
            if(j<i1) i0 +=1 ; 	/* got a carry */
            i1=j;
          }
        }
        i1 &= (~i);
      }
    }
  
    u.hilo.hi = i0;
    u.hilo.lo = i1;
    return u.d;
  }

  double ceil(double x) {
    W32s i0,i1,j0;
    W32 i,j;

    W64orDouble u;
    u.d = x;
    i0 = u.hilo.hi;
    i1 = u.hilo.lo;

    j0 = ((i0>>20)&0x7ff)-0x3ff;
    if(j0<20) {
	    if(j0<0) { 	/* raise inexact if x != 0 */
        if(huge+x>0.0) {/* return 0*sign(x) if |x|<1 */
          if(i0<0) {i0=0x80000000;i1=0;}
          else if((i0|i1)!=0) { i0=0x3ff00000;i1=0;}
        }
	    } else {
        i = (0x000fffff)>>j0;
        if(((i0&i)|i1)==0) return x; /* x is integral */
        if(huge+x>0.0) {	/* raise inexact flag */
          if(i0>0) i0 += (0x00100000)>>j0;
          i0 &= (~i); i1=0;
        }
	    }
    } else if (j0>51) {
	    if(j0==0x400) return x+x;	/* inf or NaN */
	    else return x;		/* x is integral */
    } else {
	    i = ((W32)(0xffffffff))>>(j0-20);
	    if((i1&i)==0) return x;	/* x is integral */
	    if(huge+x>0.0) { 		/* raise inexact flag */
        if(i0>0) {
          if(j0==20) i0+=1;
          else {
            j = i1 + (1<<(52-j0));
            if(j<i1) i0+=1;	/* got a carry */
            i1 = j;
          }
        }
        i1 &= (~i);
	    }
    }

    u.hilo.hi = i0;
    u.hilo.lo = i1;
    return u.d;
  }

  double trunc(double x) {
    W32s i0, j0;
    W32 i1;
    int sx;

    W64orDouble u;
    u.d = x;
    i0 = u.hilo.hi;
    i1 = u.hilo.lo;

    sx = i0 & 0x80000000;
    j0 = ((i0 >> 20) & 0x7ff) - 0x3ff;
    if (j0 < 20) {
      if (j0 < 0) {
        /* The magnitude of the number is < 1 so the result is +-0.  */
        u.hilo.hi = sx;
        u.hilo.lo = 0;
      } else {
        u.hilo.hi = sx | (i0 & ~(0x000fffff >> j0));
        u.hilo.lo = 0;
      }
    } else if (j0 > 51) {
      if (j0 == 0x400)
        /* x is inf or NaN.  */
        return x + x;
    } else {
      u.hilo.hi = i0;
      u.hilo.lo = i1 & ~(0xffffffffu >> (j0 - 20));
    }

    return u.d;
  }

  double exp2(double x) {
    return explog::__ieee754_exp2(x);
  }

  //#define FP_ILOGB0       (-2147483647)
  //#define FP_ILOGBNAN     (2147483647)

	int ilogb(double x) {
    W32s hx,lx,ix;

    W64orDouble u;
    u.d = x;
    hx = u.hilo.hi;
    lx = u.hilo.lo;

    hx &= 0x7fffffff;
    if (hx<0x00100000) {
	    if ((hx|lx)==0)
        return FP_ILOGB0;	/* ilogb(0) = FP_ILOGB0 */
	    else {		/* subnormal x */
        if (hx==0) {
          for (ix = -1043; lx>0; lx<<=1) ix -=1;
        } else {
          for (ix = -1022,hx<<=11; hx>0; hx<<=1) ix -=1;
        }
      }
	    return ix;
    } else if (hx < 0x7ff00000) {
      return (hx>>20)-1023;
    }

    return FP_ILOGBNAN;
  }

	double copysign(double x, double y) {
    W64orDouble ux, uy;
    ux.d = x;
    uy.d = y;
    ux.w = (ux.w & 0x7fffffffffffffffULL) | (uy.w & 0x8000000000000000ULL);
    return ux.d;
  }

  //
  // Optimized version without all the scalb baggage:
  //
  double significand(double x) {
    W64orDouble u;
    u.d = x;
    static const double c2e54 = 36028797018963968.0;

    if (u.ieee.exponent == 0x7ff) { // is it a NaN?
      return (x * 1.0); // 0x3ff0000000000000);
    }
    
    if (x == 0.0) return x;
    u.d = u.d * c2e54;
    u.ieee.exponent = 1023;
    
    return u.d;
  }
};
