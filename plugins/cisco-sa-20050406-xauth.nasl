#TRUSTED 8ab5e95c7a721c8704f4c5515459476aa97f2056ac2024a4ea9ffecc263a8b58696f310c3ae6f339b26426a800e47be6340636cbb576fcfa48b8489fe533dc9808a17d045a751a7b99de6cec8405f77f17d7282165394db54acc5c21b4fcd0e49d84d0d1614cb934cc2b17498ba5976927198a1252f028f910bb93630bc230709f800720abb299cbaba66c9ef9e14ef4ec485a5acd1388cb55bb7793ceb1a6f8308ea12889da977504ef7116ee8d94d4b97b231071a469a4712f2ac272fee4343d611bd467bd620a8e20e7056874449cf5e27b67a0ae04012cdd31edcaaeabd735f701ee99e6371c24a311e4725971ce750dcaa8c5409edcceb200c0c4af16239876870ff27e8d2724ca9aa986c8ce757f2da8833b8bdfed85505e390bafcf5ccd555a7e96e37871f32e730a4486a811d12b33a6da7e2e61c14602790839c00ccdc343db5fed6fbcec73a08cdd65d1a172b9d34dc9a0607807d5474039154c8d900a6dc3e60a7e401405b9c87238baee2d88d9837f6f89f846ecc8a9fc892212ca2b280392cca14dafe41b39a2d157a4a8060361cabfc76435b658d3877b96d220f9cd814f8d3d1b4b227d941e02685e316ef486f4bfcff7fa0c9899c9045f6a317b537566fb694c96b76e2f091f7ffa1bfd1d331d685792da95b567e93c6f3cabab0a73cb97663290373c5b0d7f5955e5c996cc2e597b7d23131639f3a377eb
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008042d519.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48984);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2005-1057", "CVE-2005-1058");
 script_bugtraq_id(13031, 13033);
 script_osvdb_id(15304, 15305);
 script_name(english:"Vulnerabilities in the Internet Key Exchange Xauth Implementation - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco Internetwork Operating System (IOS) Software release trains
12.2T, 12.3 and 12.3T may contain vulnerabilities in processing certain
Internet Key Exchange (IKE) Xauth messages when configured to be an
Easy VPN Server.
Successful exploitation of these vulnerabilities may permit an
unauthorized user to complete authentication and potentially access
network resources.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6d9f923");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a008042d519.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?5216373c");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050406-xauth.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/06");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCeg00277");
 script_xref(name:"CISCO-BUG-ID", value:"CSCin82407");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20050406-xauth");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(8)XW3') flag++;
else if (version == '12.3(8)XW2') flag++;
else if (version == '12.3(8)XW1') flag++;
else if (version == '12.3(8)XW') flag++;
else if (version == '12.3(8)XU2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(4)XK1') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(7)XJ2') flag++;
else if (version == '12.3(7)XJ1') flag++;
else if (version == '12.3(7)XJ') flag++;
else if (version == '12.3(7)XI2a') flag++;
else if (version == '12.3(7)XI2') flag++;
else if (version == '12.3(7)XI1c') flag++;
else if (version == '12.3(7)XI1b') flag++;
else if (version == '12.3(7)XI1') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC1') flag++;
else if (version == '12.3(2)XC') flag++;
else if (version == '12.3(2)XB3') flag++;
else if (version == '12.3(2)XB1') flag++;
else if (version == '12.3(2)XB') flag++;
else if (version == '12.3(2)XA2') flag++;
else if (version == '12.3(2)XA1') flag++;
else if (version == '12.3(2)XA') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T7') flag++;
else if (version == '12.3(4)T6') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.3(2)T8') flag++;
else if (version == '12.3(2)T7') flag++;
else if (version == '12.3(2)T6') flag++;
else if (version == '12.3(2)T5') flag++;
else if (version == '12.3(2)T4') flag++;
else if (version == '12.3(2)T3') flag++;
else if (version == '12.3(2)T2') flag++;
else if (version == '12.3(2)T1') flag++;
else if (version == '12.3(2)T') flag++;
else if (version == '12.3(5a)B2') flag++;
else if (version == '12.3(5a)B1') flag++;
else if (version == '12.3(5a)B') flag++;
else if (version == '12.3(3)B1') flag++;
else if (version == '12.3(3)B') flag++;
else if (version == '12.3(1a)B') flag++;
else if (version == '12.3(10)') flag++;
else if (version == '12.3(9b)') flag++;
else if (version == '12.3(9a)') flag++;
else if (version == '12.3(9)') flag++;
else if (version == '12.3(6c)') flag++;
else if (version == '12.3(6b)') flag++;
else if (version == '12.3(6a)') flag++;
else if (version == '12.3(6)') flag++;
else if (version == '12.3(5d)') flag++;
else if (version == '12.3(5c)') flag++;
else if (version == '12.3(5b)') flag++;
else if (version == '12.3(5a)') flag++;
else if (version == '12.3(5)') flag++;
else if (version == '12.3(3g)') flag++;
else if (version == '12.3(3f)') flag++;
else if (version == '12.3(3e)') flag++;
else if (version == '12.3(3c)') flag++;
else if (version == '12.3(3b)') flag++;
else if (version == '12.3(3a)') flag++;
else if (version == '12.3(3)') flag++;
else if (version == '12.3(1a)') flag++;
else if (version == '12.3(1)') flag++;
else if (version == '12.2(15)ZL1') flag++;
else if (version == '12.2(15)ZL') flag++;
else if (version == '12.2(15)ZJ5') flag++;
else if (version == '12.2(15)ZJ3') flag++;
else if (version == '12.2(15)ZJ2') flag++;
else if (version == '12.2(15)ZJ1') flag++;
else if (version == '12.2(15)ZJ') flag++;
else if (version == '12.2(13)ZH5') flag++;
else if (version == '12.2(13)ZH4') flag++;
else if (version == '12.2(13)ZH3') flag++;
else if (version == '12.2(13)ZH2') flag++;
else if (version == '12.2(13)ZH1') flag++;
else if (version == '12.2(13)ZH') flag++;
else if (version == '12.2(13)ZG') flag++;
else if (version == '12.2(13)ZF2') flag++;
else if (version == '12.2(13)ZF1') flag++;
else if (version == '12.2(13)ZF') flag++;
else if (version == '12.2(13)ZE') flag++;
else if (version == '12.2(13)ZD4') flag++;
else if (version == '12.2(13)ZD3') flag++;
else if (version == '12.2(13)ZD2') flag++;
else if (version == '12.2(13)ZD1') flag++;
else if (version == '12.2(13)ZD') flag++;
else if (version == '12.2(8)ZB8') flag++;
else if (version == '12.2(8)ZB7') flag++;
else if (version == '12.2(8)ZB6') flag++;
else if (version == '12.2(8)ZB5') flag++;
else if (version == '12.2(8)ZB4a') flag++;
else if (version == '12.2(8)ZB4') flag++;
else if (version == '12.2(8)ZB3') flag++;
else if (version == '12.2(8)ZB2') flag++;
else if (version == '12.2(8)ZB1') flag++;
else if (version == '12.2(8)YY4') flag++;
else if (version == '12.2(8)YY3') flag++;
else if (version == '12.2(8)YY2') flag++;
else if (version == '12.2(8)YY1') flag++;
else if (version == '12.2(8)YY') flag++;
else if (version == '12.2(11)YX1') flag++;
else if (version == '12.2(11)YX') flag++;
else if (version == '12.2(8)YW3') flag++;
else if (version == '12.2(8)YW2') flag++;
else if (version == '12.2(8)YW1') flag++;
else if (version == '12.2(8)YW') flag++;
else if (version == '12.2(11)YV1') flag++;
else if (version == '12.2(11)YV') flag++;
else if (version == '12.2(11)YU') flag++;
else if (version == '12.2(11)YR') flag++;
else if (version == '12.2(11)YQ') flag++;
else if (version == '12.2(8)YN1') flag++;
else if (version == '12.2(8)YN') flag++;
else if (version == '12.2(8)YM') flag++;
else if (version == '12.2(8)YL') flag++;
else if (version == '12.2(8)YJ1') flag++;
else if (version == '12.2(8)YJ') flag++;
else if (version == '12.2(4)YF') flag++;
else if (version == '12.2(8)YD3') flag++;
else if (version == '12.2(8)YD2') flag++;
else if (version == '12.2(8)YD1') flag++;
else if (version == '12.2(8)YD') flag++;
else if (version == '12.2(4)YB') flag++;
else if (version == '12.2(4)YA7') flag++;
else if (version == '12.2(4)YA6') flag++;
else if (version == '12.2(4)YA5') flag++;
else if (version == '12.2(4)YA4') flag++;
else if (version == '12.2(4)YA3') flag++;
else if (version == '12.2(4)YA2') flag++;
else if (version == '12.2(4)YA1') flag++;
else if (version == '12.2(4)YA') flag++;
else if (version == '12.2(4)XW') flag++;
else if (version == '12.2(4)XM4') flag++;
else if (version == '12.2(4)XM3') flag++;
else if (version == '12.2(4)XM2') flag++;
else if (version == '12.2(4)XM1') flag++;
else if (version == '12.2(4)XM') flag++;
else if (version == '12.2(4)XL6') flag++;
else if (version == '12.2(4)XL5') flag++;
else if (version == '12.2(4)XL4') flag++;
else if (version == '12.2(4)XL3') flag++;
else if (version == '12.2(4)XL2') flag++;
else if (version == '12.2(4)XL1') flag++;
else if (version == '12.2(4)XL') flag++;
else if (version == '12.2(2)XK3') flag++;
else if (version == '12.2(2)XK2') flag++;
else if (version == '12.2(2)XK1') flag++;
else if (version == '12.2(2)XK') flag++;
else if (version == '12.2(2)XJ') flag++;
else if (version == '12.2(15)T9') flag++;
else if (version == '12.2(15)T8') flag++;
else if (version == '12.2(15)T7') flag++;
else if (version == '12.2(15)T5') flag++;
else if (version == '12.2(15)T2') flag++;
else if (version == '12.2(15)T14') flag++;
else if (version == '12.2(15)T13') flag++;
else if (version == '12.2(15)T12') flag++;
else if (version == '12.2(15)T11') flag++;
else if (version == '12.2(15)T10') flag++;
else if (version == '12.2(15)T1') flag++;
else if (version == '12.2(15)T') flag++;
else if (version == '12.2(13)T9') flag++;
else if (version == '12.2(13)T8') flag++;
else if (version == '12.2(13)T5') flag++;
else if (version == '12.2(13)T4') flag++;
else if (version == '12.2(13)T3') flag++;
else if (version == '12.2(13)T2') flag++;
else if (version == '12.2(13)T14') flag++;
else if (version == '12.2(13)T13') flag++;
else if (version == '12.2(13)T12') flag++;
else if (version == '12.2(13)T11') flag++;
else if (version == '12.2(13)T10') flag++;
else if (version == '12.2(13)T1a') flag++;
else if (version == '12.2(13)T1') flag++;
else if (version == '12.2(13)T') flag++;
else if (version == '12.2(11)T9') flag++;
else if (version == '12.2(11)T8') flag++;
else if (version == '12.2(11)T6') flag++;
else if (version == '12.2(11)T5') flag++;
else if (version == '12.2(11)T4') flag++;
else if (version == '12.2(11)T3') flag++;
else if (version == '12.2(11)T2') flag++;
else if (version == '12.2(11)T11') flag++;
else if (version == '12.2(11)T10') flag++;
else if (version == '12.2(11)T1') flag++;
else if (version == '12.2(11)T') flag++;
else if (version == '12.2(8)T8') flag++;
else if (version == '12.2(8)T7') flag++;
else if (version == '12.2(8)T5') flag++;
else if (version == '12.2(8)T4') flag++;
else if (version == '12.2(8)T3') flag++;
else if (version == '12.2(8)T10') flag++;
else if (version == '12.2(8)T1') flag++;
else if (version == '12.2(8)T') flag++;
else if (version == '12.2(14)SY5') flag++;
else if (version == '12.2(14)SY4') flag++;
else if (version == '12.2(14)SY3') flag++;
else if (version == '12.2(14)SY2') flag++;
else if (version == '12.2(14)SY1') flag++;
else if (version == '12.2(14)SY') flag++;
else if (version == '12.2(18)SXD') flag++;
else if (version == '12.2(17d)SXB4') flag++;
else if (version == '12.2(17d)SXB3') flag++;
else if (version == '12.2(17d)SXB2') flag++;
else if (version == '12.2(17d)SXB1') flag++;
else if (version == '12.2(17d)SXB') flag++;
else if (version == '12.2(17b)SXA2') flag++;
else if (version == '12.2(17b)SXA') flag++;
else if (version == '12.2(17a)SX4') flag++;
else if (version == '12.2(17a)SX3') flag++;
else if (version == '12.2(17a)SX2') flag++;
else if (version == '12.2(17a)SX1') flag++;
else if (version == '12.2(17a)SX') flag++;
else if (version == '12.2(14)SU1') flag++;
else if (version == '12.2(14)SU') flag++;
else if (version == '12.2(15)CZ') flag++;
else if (version == '12.2(11)CY') flag++;
else if (version == '12.2(15)CX1') flag++;
else if (version == '12.2(15)CX') flag++;
else if (version == '12.2(11)CX1') flag++;
else if (version == '12.2(11)CX') flag++;
else if (version == '12.2(15)BZ2') flag++;
else if (version == '12.2(8)BY2') flag++;
else if (version == '12.2(8)BY1') flag++;
else if (version == '12.2(8)BY') flag++;
else if (version == '12.2(16)BX3') flag++;
else if (version == '12.2(16)BX2') flag++;
else if (version == '12.2(16)BX1') flag++;
else if (version == '12.2(16)BX') flag++;
else if (version == '12.2(15)BX') flag++;
else if (version == '12.2(15)BC2d') flag++;
else if (version == '12.2(15)BC2c') flag++;
else if (version == '12.2(15)BC2b') flag++;
else if (version == '12.2(15)BC2a') flag++;
else if (version == '12.2(15)BC2') flag++;
else if (version == '12.2(15)BC1e') flag++;
else if (version == '12.2(15)BC1d') flag++;
else if (version == '12.2(15)BC1c') flag++;
else if (version == '12.2(15)BC1b') flag++;
else if (version == '12.2(15)BC1a') flag++;
else if (version == '12.2(15)BC1') flag++;
else if (version == '12.2(11)BC3d') flag++;
else if (version == '12.2(11)BC3c') flag++;
else if (version == '12.2(11)BC3b') flag++;
else if (version == '12.2(11)BC3a') flag++;
else if (version == '12.2(11)BC3') flag++;
else if (version == '12.2(11)BC2') flag++;
else if (version == '12.2(11)BC1b') flag++;
else if (version == '12.2(11)BC1a') flag++;
else if (version == '12.2(11)BC1') flag++;
else if (version == '12.2(8)BC2a') flag++;
else if (version == '12.2(8)BC2') flag++;
else if (version == '12.2(8)BC1') flag++;
else if (version == '12.2(16)B2') flag++;
else if (version == '12.2(16)B1') flag++;
else if (version == '12.2(16)B') flag++;
else if (version == '12.2(15)B') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"crypt\s+map\s+[^\r\n]+\s+client\s+authentication\s+list\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
