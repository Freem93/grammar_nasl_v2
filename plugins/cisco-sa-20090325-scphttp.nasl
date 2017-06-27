#TRUSTED 10230987305cd4bc7c3ad4117606621938eecb53d4695a761781c0e9811c9635c2054b171d86c55d7c3696df004ac26c334090dc98f83234791081250b5c0b781f258e77b0a81967769c7eb1cb932952f5caa2619639b6fd4714c96174ae5a1c5bd8ca69574882a16ad4c9bbe38b71750343cdf9741732dd3ff71db468854a2e72d2e390c71e2a7fe9ec49f842b83c44bbe74d04cf3dbd9bc98f1974c688a4eebad240f7ce35af148fecfa78a31236f6bf9995219beed7d552e02e9372e45f14de914ad3cb84ae2485f534ee12a00b27a7d750d497e2282d29ce183a27bc2953b4ba9da7c88eb1aa7c1cdbbdb93f69923212ffb5b0c4af3cb9852a01bbf66115b2734618370695365ae47fbbf46dcf15d031b1e7bb344940cb9458d279791ec3dc036334e1dfc912b74dbfb28336dad8ca9a8bf02e339e4b040202f1d17f61b90ef9264104f4cc2dd8bb8ade742bdc958b01f48d41ee767fbf852791694454c8d1eae681a3bf23ebb3fb34db5d64d4664080a2a933f77d2939a5f962aab243539144bb8760f45b51c24245b7e8461bc593abc4ef56582f23c4971f30301f632c0f5885ad848f8c45883768074be6c1f0f910068c377274cc3f311fcf117472729f9bf1d36f2a851f42af4cbc81325fe72a1cfa78e518a876da480ee74f0aaf1bb18d7688fec5fad8ab92d114e915f7695e1677d7e22af2bce0b1213c52661370
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c22.shtml

include("compat.inc");

if (description)
{
 script_id(49032);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2009-0637");
 script_bugtraq_id(34247);
 script_osvdb_id(53132);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv38166");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090325-scp");

 script_name(english:"Cisco IOS Software Secure Copy Privilege Escalation Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"The server side of the Secure Copy (SCP) implementation in Cisco IOS
software contains a vulnerability that could allow authenticated users
with an attached command-line interface (CLI) view to transfer files to
and from a Cisco IOS device that is configured to be an SCP server,
regardless of what users are authorized to do, per the CLI view
configuration. This vulnerability could allow valid users to retrieve
or write to any file on the device's file system, including the
device's saved configuration and Cisco IOS image files, even if the CLI
view attached to the user does not allow it. This configuration file
may include passwords or other sensitive information.

The Cisco IOS SCP server is an optional service that is disabled by
default. CLI views are a fundamental component of the Cisco IOS
Role-Based CLI Access feature, which is also disabled by default.
Devices that are not specifically configured to enable the Cisco IOS
SCP server, or that are configured to use it but do not use role-based
CLI access, are not affected by this vulnerability.

This vulnerability does not apply to the Cisco IOS SCP client feature.
Cisco has released free software updates that address this
vulnerability.

There are no workarounds available for this vulnerability apart from
disabling either the SCP server or the CLI view feature if these
services are not required by administrators.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4db32be");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c22.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87fb42f7");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090325-scp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

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
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY5') flag++;
else if (version == '12.4(15)XY4') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW9') flag++;
else if (version == '12.4(11)XW8') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(6)XT2') flag++;
else if (version == '12.4(6)XT1') flag++;
else if (version == '12.4(6)XT') flag++;
else if (version == '12.4(15)XR4') flag++;
else if (version == '12.4(15)XR3') flag++;
else if (version == '12.4(15)XR2') flag++;
else if (version == '12.4(15)XR1') flag++;
else if (version == '12.4(15)XR') flag++;
else if (version == '12.4(15)XQ1') flag++;
else if (version == '12.4(15)XQ') flag++;
else if (version == '12.4(6)XP') flag++;
else if (version == '12.4(15)XN') flag++;
else if (version == '12.4(15)XM2') flag++;
else if (version == '12.4(15)XM1') flag++;
else if (version == '12.4(15)XM') flag++;
else if (version == '12.4(15)XL3') flag++;
else if (version == '12.4(15)XL2') flag++;
else if (version == '12.4(15)XL1') flag++;
else if (version == '12.4(15)XL') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(9)XG3') flag++;
else if (version == '12.4(9)XG2') flag++;
else if (version == '12.4(9)XG1') flag++;
else if (version == '12.4(9)XG') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(4)XD9') flag++;
else if (version == '12.4(4)XD8') flag++;
else if (version == '12.4(4)XD7') flag++;
else if (version == '12.4(4)XD5') flag++;
else if (version == '12.4(4)XD4') flag++;
else if (version == '12.4(4)XD2') flag++;
else if (version == '12.4(4)XD11') flag++;
else if (version == '12.4(4)XD10') flag++;
else if (version == '12.4(4)XD1') flag++;
else if (version == '12.4(4)XD') flag++;
else if (version == '12.4(4)XC7') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(2)XB9') flag++;
else if (version == '12.4(2)XB8') flag++;
else if (version == '12.4(2)XB7') flag++;
else if (version == '12.4(2)XB6') flag++;
else if (version == '12.4(2)XB5') flag++;
else if (version == '12.4(2)XB4') flag++;
else if (version == '12.4(2)XB3') flag++;
else if (version == '12.4(2)XB2') flag++;
else if (version == '12.4(2)XB10') flag++;
else if (version == '12.4(2)XB1') flag++;
else if (version == '12.4(2)XB') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(22)T') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(15)T8') flag++;
else if (version == '12.4(15)T7') flag++;
else if (version == '12.4(15)T6') flag++;
else if (version == '12.4(15)T5') flag++;
else if (version == '12.4(15)T4') flag++;
else if (version == '12.4(15)T3') flag++;
else if (version == '12.4(15)T2') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T7') flag++;
else if (version == '12.4(9)T6') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(6)T9') flag++;
else if (version == '12.4(6)T8') flag++;
else if (version == '12.4(6)T7') flag++;
else if (version == '12.4(6)T6') flag++;
else if (version == '12.4(6)T5') flag++;
else if (version == '12.4(6)T4') flag++;
else if (version == '12.4(6)T3') flag++;
else if (version == '12.4(6)T2') flag++;
else if (version == '12.4(6)T11') flag++;
else if (version == '12.4(6)T10') flag++;
else if (version == '12.4(6)T1') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(4)T8') flag++;
else if (version == '12.4(4)T7') flag++;
else if (version == '12.4(4)T6') flag++;
else if (version == '12.4(4)T5') flag++;
else if (version == '12.4(4)T4') flag++;
else if (version == '12.4(4)T3') flag++;
else if (version == '12.4(4)T2') flag++;
else if (version == '12.4(4)T1') flag++;
else if (version == '12.4(4)T') flag++;
else if (version == '12.4(2)T6') flag++;
else if (version == '12.4(2)T5') flag++;
else if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(15)SW2') flag++;
else if (version == '12.4(15)SW1') flag++;
else if (version == '12.4(15)SW') flag++;
else if (version == '12.4(11)SW3') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(19)MR1') flag++;
else if (version == '12.4(19)MR') flag++;
else if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(9)MR') flag++;
else if (version == '12.4(6)MR1') flag++;
else if (version == '12.4(6)MR') flag++;
else if (version == '12.4(4)MR1') flag++;
else if (version == '12.4(4)MR') flag++;
else if (version == '12.4(2)MR1') flag++;
else if (version == '12.4(2)MR') flag++;
else if (version == '12.4(22)MD') flag++;
else if (version == '12.4(15)MD2') flag++;
else if (version == '12.4(15)MD1') flag++;
else if (version == '12.4(15)MD') flag++;
else if (version == '12.4(11)MD6') flag++;
else if (version == '12.4(11)MD5') flag++;
else if (version == '12.4(11)MD4') flag++;
else if (version == '12.4(11)MD3') flag++;
else if (version == '12.4(11)MD2') flag++;
else if (version == '12.4(11)MD1') flag++;
else if (version == '12.4(11)MD') flag++;
else if (version == '12.4(10b)JX') flag++;
else if (version == '12.4(3g)JX1') flag++;
else if (version == '12.4(3g)JX') flag++;
else if (version == '12.4(3g)JMC2') flag++;
else if (version == '12.4(3g)JMC1') flag++;
else if (version == '12.4(3g)JMC') flag++;
else if (version == '12.4(3g)JMB') flag++;
else if (version == '12.4(3g)JMA1') flag++;
else if (version == '12.4(3g)JMA') flag++;
else if (version == '12.4(3)JL1') flag++;
else if (version == '12.4(3)JL') flag++;
else if (version == '12.4(3)JK3') flag++;
else if (version == '12.4(3)JK2') flag++;
else if (version == '12.4(3)JK1') flag++;
else if (version == '12.4(3)JK') flag++;
else if (version == '12.4(10b)JDA2') flag++;
else if (version == '12.4(10b)JDA1') flag++;
else if (version == '12.4(10b)JDA') flag++;
else if (version == '12.4(18a)JA1') flag++;
else if (version == '12.4(18a)JA') flag++;
else if (version == '12.4(16b)JA1') flag++;
else if (version == '12.4(16b)JA') flag++;
else if (version == '12.4(13d)JA') flag++;
else if (version == '12.4(10b)JA4') flag++;
else if (version == '12.4(10b)JA3') flag++;
else if (version == '12.4(10b)JA2') flag++;
else if (version == '12.4(10b)JA1') flag++;
else if (version == '12.4(10b)JA') flag++;
else if (version == '12.4(3g)JA2') flag++;
else if (version == '12.4(3g)JA1') flag++;
else if (version == '12.4(3g)JA') flag++;
else if (version == '12.4(23)') flag++;
else if (version == '12.4(21a)') flag++;
else if (version == '12.4(21)') flag++;
else if (version == '12.4(19b)') flag++;
else if (version == '12.4(19a)') flag++;
else if (version == '12.4(19)') flag++;
else if (version == '12.4(18c)') flag++;
else if (version == '12.4(18b)') flag++;
else if (version == '12.4(18a)') flag++;
else if (version == '12.4(18)') flag++;
else if (version == '12.4(17b)') flag++;
else if (version == '12.4(17a)') flag++;
else if (version == '12.4(17)') flag++;
else if (version == '12.4(16b)') flag++;
else if (version == '12.4(16a)') flag++;
else if (version == '12.4(16)') flag++;
else if (version == '12.4(13f)') flag++;
else if (version == '12.4(13e)') flag++;
else if (version == '12.4(13d)') flag++;
else if (version == '12.4(13c)') flag++;
else if (version == '12.4(13b)') flag++;
else if (version == '12.4(13a)') flag++;
else if (version == '12.4(13)') flag++;
else if (version == '12.4(12c)') flag++;
else if (version == '12.4(12b)') flag++;
else if (version == '12.4(12a)') flag++;
else if (version == '12.4(12)') flag++;
else if (version == '12.4(10c)') flag++;
else if (version == '12.4(10b)') flag++;
else if (version == '12.4(10a)') flag++;
else if (version == '12.4(10)') flag++;
else if (version == '12.4(8d)') flag++;
else if (version == '12.4(8c)') flag++;
else if (version == '12.4(8b)') flag++;
else if (version == '12.4(8a)') flag++;
else if (version == '12.4(8)') flag++;
else if (version == '12.4(7h)') flag++;
else if (version == '12.4(7g)') flag++;
else if (version == '12.4(7f)') flag++;
else if (version == '12.4(7e)') flag++;
else if (version == '12.4(7d)') flag++;
else if (version == '12.4(7c)') flag++;
else if (version == '12.4(7b)') flag++;
else if (version == '12.4(7a)') flag++;
else if (version == '12.4(7)') flag++;
else if (version == '12.4(5c)') flag++;
else if (version == '12.4(5b)') flag++;
else if (version == '12.4(5a)') flag++;
else if (version == '12.4(5)') flag++;
else if (version == '12.4(3j)') flag++;
else if (version == '12.4(3i)') flag++;
else if (version == '12.4(3h)') flag++;
else if (version == '12.4(3g)') flag++;
else if (version == '12.4(3f)') flag++;
else if (version == '12.4(3e)') flag++;
else if (version == '12.4(3d)') flag++;
else if (version == '12.4(3c)') flag++;
else if (version == '12.4(3b)') flag++;
else if (version == '12.4(3a)') flag++;
else if (version == '12.4(3)') flag++;
else if (version == '12.4(1c)') flag++;
else if (version == '12.4(1b)') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(8)ZA') flag++;
else if (version == '12.3(11)YZ2') flag++;
else if (version == '12.3(11)YZ1') flag++;
else if (version == '12.3(11)YZ') flag++;
else if (version == '12.3(14)YX9') flag++;
else if (version == '12.3(14)YX8') flag++;
else if (version == '12.3(14)YX7') flag++;
else if (version == '12.3(14)YX4') flag++;
else if (version == '12.3(14)YX3') flag++;
else if (version == '12.3(14)YX2') flag++;
else if (version == '12.3(14)YX13') flag++;
else if (version == '12.3(14)YX12') flag++;
else if (version == '12.3(14)YX11') flag++;
else if (version == '12.3(14)YX10') flag++;
else if (version == '12.3(14)YX1') flag++;
else if (version == '12.3(14)YX') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS2') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ8') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(14)YM9') flag++;
else if (version == '12.3(14)YM8') flag++;
else if (version == '12.3(14)YM7') flag++;
else if (version == '12.3(14)YM6') flag++;
else if (version == '12.3(14)YM5') flag++;
else if (version == '12.3(14)YM4') flag++;
else if (version == '12.3(14)YM3') flag++;
else if (version == '12.3(14)YM2') flag++;
else if (version == '12.3(14)YM12') flag++;
else if (version == '12.3(14)YM11') flag++;
else if (version == '12.3(14)YM10') flag++;
else if (version == '12.3(11)YK3') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(11)YJ') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG6') flag++;
else if (version == '12.3(8)YG5') flag++;
else if (version == '12.3(8)YG4') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XY7') flag++;
else if (version == '12.3(8)XY6') flag++;
else if (version == '12.3(8)XY5') flag++;
else if (version == '12.3(8)XY4') flag++;
else if (version == '12.3(8)XY3') flag++;
else if (version == '12.3(8)XY2') flag++;
else if (version == '12.3(8)XY1') flag++;
else if (version == '12.3(8)XY') flag++;
else if (version == '12.3(8)XX2d') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(8)XW3') flag++;
else if (version == '12.3(8)XW2') flag++;
else if (version == '12.3(8)XW1') flag++;
else if (version == '12.3(8)XW') flag++;
else if (version == '12.3(8)XU5') flag++;
else if (version == '12.3(8)XU4') flag++;
else if (version == '12.3(8)XU3') flag++;
else if (version == '12.3(8)XU2') flag++;
else if (version == '12.3(8)XU1') flag++;
else if (version == '12.3(8)XU') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR7') flag++;
else if (version == '12.3(7)XR6') flag++;
else if (version == '12.3(7)XR5') flag++;
else if (version == '12.3(7)XR4') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(4)XQ1') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(4)XK4') flag++;
else if (version == '12.3(4)XK3') flag++;
else if (version == '12.3(4)XK2') flag++;
else if (version == '12.3(4)XK1') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(7)XJ2') flag++;
else if (version == '12.3(7)XJ1') flag++;
else if (version == '12.3(7)XJ') flag++;
else if (version == '12.3(7)XI9') flag++;
else if (version == '12.3(7)XI8d') flag++;
else if (version == '12.3(7)XI8c') flag++;
else if (version == '12.3(7)XI8a') flag++;
else if (version == '12.3(7)XI8') flag++;
else if (version == '12.3(7)XI7b') flag++;
else if (version == '12.3(7)XI7a') flag++;
else if (version == '12.3(7)XI7') flag++;
else if (version == '12.3(7)XI6') flag++;
else if (version == '12.3(7)XI5') flag++;
else if (version == '12.3(7)XI4') flag++;
else if (version == '12.3(7)XI3') flag++;
else if (version == '12.3(7)XI2a') flag++;
else if (version == '12.3(7)XI2') flag++;
else if (version == '12.3(7)XI10a') flag++;
else if (version == '12.3(7)XI10') flag++;
else if (version == '12.3(7)XI1c') flag++;
else if (version == '12.3(7)XI1b') flag++;
else if (version == '12.3(7)XI1') flag++;
else if (version == '12.3(4)XG5') flag++;
else if (version == '12.3(4)XG4') flag++;
else if (version == '12.3(4)XG3') flag++;
else if (version == '12.3(4)XG2') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T9') flag++;
else if (version == '12.3(11)T8') flag++;
else if (version == '12.3(11)T7') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T11') flag++;
else if (version == '12.3(11)T10') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T9') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T11') flag++;
else if (version == '12.3(8)T10') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;
else if (version == '12.3(7)T9') flag++;
else if (version == '12.3(7)T8') flag++;
else if (version == '12.3(7)T7') flag++;
else if (version == '12.3(7)T6') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T12') flag++;
else if (version == '12.3(7)T11') flag++;
else if (version == '12.3(7)T10') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(11)JX1') flag++;
else if (version == '12.3(11)JX') flag++;
else if (version == '12.3(7)JX9') flag++;
else if (version == '12.3(7)JX8') flag++;
else if (version == '12.3(7)JX7') flag++;
else if (version == '12.3(7)JX6') flag++;
else if (version == '12.3(7)JX5') flag++;
else if (version == '12.3(7)JX4') flag++;
else if (version == '12.3(7)JX3') flag++;
else if (version == '12.3(7)JX2') flag++;
else if (version == '12.3(7)JX11') flag++;
else if (version == '12.3(7)JX10') flag++;
else if (version == '12.3(7)JX1') flag++;
else if (version == '12.3(7)JX') flag++;
else if (version == '12.3(8)JK1') flag++;
else if (version == '12.3(8)JEC2') flag++;
else if (version == '12.3(8)JEC1') flag++;
else if (version == '12.3(8)JEB1') flag++;
else if (version == '12.3(8)JEB') flag++;
else if (version == '12.3(8)JEA3') flag++;
else if (version == '12.3(8)JEA2') flag++;
else if (version == '12.3(8)JEA1') flag++;
else if (version == '12.3(8)JEA') flag++;
else if (version == '12.3(11)JA4') flag++;
else if (version == '12.3(11)JA3') flag++;
else if (version == '12.3(11)JA1') flag++;
else if (version == '12.3(11)JA') flag++;
else if (version == '12.3(8)JA2') flag++;
else if (version == '12.3(8)JA1') flag++;
else if (version == '12.3(8)JA') flag++;
else if (version == '12.3(7)JA5') flag++;
else if (version == '12.3(7)JA4') flag++;
else if (version == '12.3(7)JA3') flag++;
else if (version == '12.3(7)JA2') flag++;
else if (version == '12.3(7)JA1') flag++;
else if (version == '12.3(7)JA') flag++;
else if (version == '12.2(33)XN1') flag++;
else if (version == '12.2(33)SXI') flag++;
else if (version == '12.2(33)STE0') flag++;
else if (version == '12.2(33)SRD') flag++;
else if (version == '12.2(33)SRC3') flag++;
else if (version == '12.2(33)SRC2') flag++;
else if (version == '12.2(33)SRC1') flag++;
else if (version == '12.2(33)SRC') flag++;
else if (version == '12.2(33)SRB5') flag++;
else if (version == '12.2(33)SRB4') flag++;
else if (version == '12.2(33)SRB3') flag++;
else if (version == '12.2(33)SRB2') flag++;
else if (version == '12.2(33)SRB1') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(44)SQ') flag++;
else if (version == '12.2(50)SG1') flag++;
else if (version == '12.2(50)SG') flag++;
else if (version == '12.2(46)SG1') flag++;
else if (version == '12.2(46)SG') flag++;
else if (version == '12.2(44)SG1') flag++;
else if (version == '12.2(44)SG') flag++;
else if (version == '12.2(46)SE2') flag++;
else if (version == '12.2(46)SE1') flag++;
else if (version == '12.2(46)SE') flag++;
else if (version == '12.2(44)SE5') flag++;
else if (version == '12.2(44)SE4') flag++;
else if (version == '12.2(44)SE3') flag++;
else if (version == '12.2(44)SE2') flag++;
else if (version == '12.2(44)SE1') flag++;
else if (version == '12.2(44)SE') flag++;
else if (version == '12.2(33)SCB') flag++;
else if (version == '12.2(33)SCA2') flag++;
else if (version == '12.2(33)SCA1') flag++;
else if (version == '12.2(33)SCA') flag++;
else if (version == '12.2(33)SB3') flag++;
else if (version == '12.2(33)SB2') flag++;
else if (version == '12.2(33)SB1') flag++;
else if (version == '12.2(33)SB') flag++;
else if (version == '12.2(33)IRB') flag++;
else if (version == '12.2(33)IRA') flag++;
else if (version == '12.2(46)EY') flag++;
else if (version == '12.2(44)EY') flag++;
else if (version == '12.2(46)EX') flag++;
else if (version == '12.2(44)EX1') flag++;
else if (version == '12.2(44)EX') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"parser view ", multiline:TRUE, string:buf)) && (preg(pattern:"ip scp server enable", multiline:TRUE, string:buf)) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
