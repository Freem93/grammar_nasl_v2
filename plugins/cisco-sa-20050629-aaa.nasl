#TRUSTED 9f9698753ad3402bb2ce6fb7e8807496d8939e612a5421e1c167fc42b167c2dc258bf498c9ae6435f81e38666e65426b7f9660ad8ea81993e7b16692497057b4cf122351d1eb8e2edc2652365997d289b12b0f78fe5b8d0d77ccb9e6a5e9267e0eea4ffa930840224188f690df63256d64b997570e690d21562c994e36da51acd60f83dd7813d4aaf91869b6a65f6b7ebda72a7cc4a800e1836004862e47cf906b284ef51088000150b2e8dedd2308a6c8724475573cdd071417e086526f04656165c9f159805d481b71865f646bee0f528cd15d63810006ea5ee1d9d4dc626d7e229972204d068b7206fddb84119bd437c7770a490c59d049bca18e070caae8ae06cd208ac9e82d967184d874ee939f4953afa813e3b33b697bceb85fd5db1554848342ed04edf04b0c077d72f9c07b754459b90f7dc74d647fdd9147ed322a9da858d2d561e83d9da3acf52b25e10f8fafc36c89eb7180b80acce02be0d0f99a263130883a7dba68d7b74fb8ec3e81df5ba47a2d176888c6c3ab5c8eb49a706705de3fead13b73d72a6aa9a794e75c6189ca7800143f784982146f062f1db0de2e80d13987fadbd2e61bae1e53e9a70c9018822801205ae0cfb0f8661d01fb021201adb15b00ec96e3304e455813c8ea7b2a326cba44be1562bc12becaaaaec8b4bc203e6bc0c69d3bb43b3b8440dc518a7e30ec72f0804f3e1eaa8a890775
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20050629-aaa.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(48986);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_xref(name:"CISCO-BUG-ID", value:"CSCee45312");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20050629-aaa");

  script_name(english:"RADIUS Authentication Bypass (cisco-sa-20050629-aaa)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Remote Authentication Dial In User Service (RADIUS) authentication on
a device that is running certain versions of Cisco Internetworking
Operating System (IOS) and configured with a fallback method to none
can be bypassed. Systems that are configured for other authentication
methods or that are not configured with a fallback method to none are
not affected. Only the systems that are running certain versions of
Cisco IOS are affected. Not all configurations using RADIUS and none
are vulnerable to this issue. Some configurations using RADIUS, none
and an additional method are not affected. Cisco has made free
software available to address this vulnerability. There are
workarounds available to mitigate the effects of the vulnerability.
The vulnerabilities are documented as the following Cisco Bug ID:
CSCee45312 -- Radius authentication bypass when configured with a none
fallback method."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20050629-aaa
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b981b4d9"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050629-aaa."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if ( version == '12.2(1)MB1' ) flag++;
if ( version == '12.2(1)XD' ) flag++;
if ( version == '12.2(1)XD1' ) flag++;
if ( version == '12.2(1)XD2' ) flag++;
if ( version == '12.2(1)XD3' ) flag++;
if ( version == '12.2(1)XD4' ) flag++;
if ( version == '12.2(1)XE' ) flag++;
if ( version == '12.2(1)XE1' ) flag++;
if ( version == '12.2(1)XE2' ) flag++;
if ( version == '12.2(11)BC1' ) flag++;
if ( version == '12.2(11)BC1a' ) flag++;
if ( version == '12.2(11)BC1b' ) flag++;
if ( version == '12.2(11)BC2' ) flag++;
if ( version == '12.2(11)BC2a' ) flag++;
if ( version == '12.2(11)BC3' ) flag++;
if ( version == '12.2(11)BC3a' ) flag++;
if ( version == '12.2(11)BC3b' ) flag++;
if ( version == '12.2(11)BC3c' ) flag++;
if ( version == '12.2(11)BC3d' ) flag++;
if ( version == '12.2(11)CX' ) flag++;
if ( version == '12.2(11)CY' ) flag++;
if ( version == '12.2(11)JA' ) flag++;
if ( version == '12.2(11)JA1' ) flag++;
if ( version == '12.2(11)JA2' ) flag++;
if ( version == '12.2(11)JA3' ) flag++;
if ( version == '12.2(11)T' ) flag++;
if ( version == '12.2(11)T1' ) flag++;
if ( version == '12.2(11)T10' ) flag++;
if ( version == '12.2(11)T11' ) flag++;
if ( version == '12.2(11)T2' ) flag++;
if ( version == '12.2(11)T3' ) flag++;
if ( version == '12.2(11)T4' ) flag++;
if ( version == '12.2(11)T5' ) flag++;
if ( version == '12.2(11)T6' ) flag++;
if ( version == '12.2(11)T8' ) flag++;
if ( version == '12.2(11)T9' ) flag++;
if ( version == '12.2(11)YP3' ) flag++;
if ( version == '12.2(11)YQ' ) flag++;
if ( version == '12.2(11)YR' ) flag++;
if ( version == '12.2(11)YT' ) flag++;
if ( version == '12.2(11)YT1' ) flag++;
if ( version == '12.2(11)YT2' ) flag++;
if ( version == '12.2(11)YU' ) flag++;
if ( version == '12.2(11)YV' ) flag++;
if ( version == '12.2(11)YV1' ) flag++;
if ( version == '12.2(11)ZC' ) flag++;
if ( version == '12.2(13)JA' ) flag++;
if ( version == '12.2(13)JA1' ) flag++;
if ( version == '12.2(13)JA2' ) flag++;
if ( version == '12.2(13)JA3' ) flag++;
if ( version == '12.2(13)JA4' ) flag++;
if ( version == '12.2(13)T' ) flag++;
if ( version == '12.2(13)T1' ) flag++;
if ( version == '12.2(13)T10' ) flag++;
if ( version == '12.2(13)T11' ) flag++;
if ( version == '12.2(13)T12' ) flag++;
if ( version == '12.2(13)T13' ) flag++;
if ( version == '12.2(13)T14' ) flag++;
if ( version == '12.2(13)T16' ) flag++;
if ( version == '12.2(13)T1a' ) flag++;
if ( version == '12.2(13)T2' ) flag++;
if ( version == '12.2(13)T3' ) flag++;
if ( version == '12.2(13)T4' ) flag++;
if ( version == '12.2(13)T5' ) flag++;
if ( version == '12.2(13)T8' ) flag++;
if ( version == '12.2(13)T9' ) flag++;
if ( version == '12.2(13)ZC' ) flag++;
if ( version == '12.2(13)ZD' ) flag++;
if ( version == '12.2(13)ZD1' ) flag++;
if ( version == '12.2(13)ZD2' ) flag++;
if ( version == '12.2(13)ZD3' ) flag++;
if ( version == '12.2(13)ZD4' ) flag++;
if ( version == '12.2(13)ZE' ) flag++;
if ( version == '12.2(13)ZF' ) flag++;
if ( version == '12.2(13)ZF1' ) flag++;
if ( version == '12.2(13)ZF2' ) flag++;
if ( version == '12.2(13)ZG' ) flag++;
if ( version == '12.2(13)ZH' ) flag++;
if ( version == '12.2(13)ZH1' ) flag++;
if ( version == '12.2(13)ZH2' ) flag++;
if ( version == '12.2(13)ZH3' ) flag++;
if ( version == '12.2(13)ZH4' ) flag++;
if ( version == '12.2(13)ZH5' ) flag++;
if ( version == '12.2(13)ZH6' ) flag++;
if ( version == '12.2(13)ZH7' ) flag++;
if ( version == '12.2(13)ZP' ) flag++;
if ( version == '12.2(13)ZP1' ) flag++;
if ( version == '12.2(13)ZP2' ) flag++;
if ( version == '12.2(13)ZP3' ) flag++;
if ( version == '12.2(13)ZP4' ) flag++;
if ( version == '12.2(15)B' ) flag++;
if ( version == '12.2(15)BC1' ) flag++;
if ( version == '12.2(15)BC1a' ) flag++;
if ( version == '12.2(15)BC1b' ) flag++;
if ( version == '12.2(15)BC1c' ) flag++;
if ( version == '12.2(15)BC1d' ) flag++;
if ( version == '12.2(15)BC1e' ) flag++;
if ( version == '12.2(15)BC1f' ) flag++;
if ( version == '12.2(15)BC1g' ) flag++;
if ( version == '12.2(15)BC2' ) flag++;
if ( version == '12.2(15)BC2a' ) flag++;
if ( version == '12.2(15)BC2b' ) flag++;
if ( version == '12.2(15)BC2c' ) flag++;
if ( version == '12.2(15)BC2d' ) flag++;
if ( version == '12.2(15)BC2e' ) flag++;
if ( version == '12.2(15)BC2f' ) flag++;
if ( version == '12.2(15)BC2g' ) flag++;
if ( version == '12.2(15)BC2h' ) flag++;
if ( version == '12.2(15)BC2i' ) flag++;
if ( version == '12.2(15)BX' ) flag++;
if ( version == '12.2(15)BZ2' ) flag++;
if ( version == '12.2(15)CX' ) flag++;
if ( version == '12.2(15)CX1' ) flag++;
if ( version == '12.2(15)CZ' ) flag++;
if ( version == '12.2(15)CZ1' ) flag++;
if ( version == '12.2(15)CZ2' ) flag++;
if ( version == '12.2(15)CZ3' ) flag++;
if ( version == '12.2(15)JA' ) flag++;
if ( version == '12.2(15)JK' ) flag++;
if ( version == '12.2(15)JK1' ) flag++;
if ( version == '12.2(15)JK2' ) flag++;
if ( version == '12.2(15)JK3' ) flag++;
if ( version == '12.2(15)JK4' ) flag++;
if ( version == '12.2(15)MC1' ) flag++;
if ( version == '12.2(15)MC1a' ) flag++;
if ( version == '12.2(15)MC1b' ) flag++;
if ( version == '12.2(15)MC1c' ) flag++;
if ( version == '12.2(15)MC2' ) flag++;
if ( version == '12.2(15)MC2a' ) flag++;
if ( version == '12.2(15)MC2b' ) flag++;
if ( version == '12.2(15)MC2c' ) flag++;
if ( version == '12.2(15)MC2e' ) flag++;
if ( version == '12.2(15)MC2f' ) flag++;
if ( version == '12.2(15)MC2g' ) flag++;
if ( version == '12.2(15)T' ) flag++;
if ( version == '12.2(15)T1' ) flag++;
if ( version == '12.2(15)T10' ) flag++;
if ( version == '12.2(15)T11' ) flag++;
if ( version == '12.2(15)T12' ) flag++;
if ( version == '12.2(15)T13' ) flag++;
if ( version == '12.2(15)T14' ) flag++;
if ( version == '12.2(15)T15' ) flag++;
if ( version == '12.2(15)T16' ) flag++;
if ( version == '12.2(15)T2' ) flag++;
if ( version == '12.2(15)T4' ) flag++;
if ( version == '12.2(15)T4e' ) flag++;
if ( version == '12.2(15)T5' ) flag++;
if ( version == '12.2(15)T7' ) flag++;
if ( version == '12.2(15)T8' ) flag++;
if ( version == '12.2(15)T9' ) flag++;
if ( version == '12.2(15)XR' ) flag++;
if ( version == '12.2(15)XR1' ) flag++;
if ( version == '12.2(15)XR2' ) flag++;
if ( version == '12.2(15)ZJ' ) flag++;
if ( version == '12.2(15)ZJ1' ) flag++;
if ( version == '12.2(15)ZJ2' ) flag++;
if ( version == '12.2(15)ZJ3' ) flag++;
if ( version == '12.2(15)ZJ5' ) flag++;
if ( version == '12.2(15)ZL' ) flag++;
if ( version == '12.2(15)ZL1' ) flag++;
if ( version == '12.2(16)B' ) flag++;
if ( version == '12.2(16)B1' ) flag++;
if ( version == '12.2(16)B2' ) flag++;
if ( version == '12.2(16)BX' ) flag++;
if ( version == '12.2(16)BX1' ) flag++;
if ( version == '12.2(16)BX2' ) flag++;
if ( version == '12.2(16)BX3' ) flag++;
if ( version == '12.2(18)SXD' ) flag++;
if ( version == '12.2(18)SXD1' ) flag++;
if ( version == '12.2(18)SXD2' ) flag++;
if ( version == '12.2(18)SXD3' ) flag++;
if ( version == '12.2(18)SXD4' ) flag++;
if ( version == '12.2(18)SXE' ) flag++;
if ( version == '12.2(18)SXE1' ) flag++;
if ( version == '12.2(2)BX' ) flag++;
if ( version == '12.2(2)BX1' ) flag++;
if ( version == '12.2(2)BY' ) flag++;
if ( version == '12.2(2)BY1' ) flag++;
if ( version == '12.2(2)BY2' ) flag++;
if ( version == '12.2(2)BY3' ) flag++;
if ( version == '12.2(2)XB1' ) flag++;
if ( version == '12.2(2)XB10' ) flag++;
if ( version == '12.2(2)XB11' ) flag++;
if ( version == '12.2(2)XB12' ) flag++;
if ( version == '12.2(2)XB14' ) flag++;
if ( version == '12.2(2)XB15' ) flag++;
if ( version == '12.2(2)XB2' ) flag++;
if ( version == '12.2(2)XB3' ) flag++;
if ( version == '12.2(2)XB5' ) flag++;
if ( version == '12.2(2)XB6' ) flag++;
if ( version == '12.2(2)XB7' ) flag++;
if ( version == '12.2(2)XB8' ) flag++;
if ( version == '12.2(2)XC' ) flag++;
if ( version == '12.2(2)XC1' ) flag++;
if ( version == '12.2(2)XC2' ) flag++;
if ( version == '12.2(2)XG' ) flag++;
if ( version == '12.2(2)XG1' ) flag++;
if ( version == '12.2(2)XH' ) flag++;
if ( version == '12.2(2)XH1' ) flag++;
if ( version == '12.2(2)XH2' ) flag++;
if ( version == '12.2(2)XI' ) flag++;
if ( version == '12.2(2)XI1' ) flag++;
if ( version == '12.2(2)XI2' ) flag++;
if ( version == '12.2(2)XJ' ) flag++;
if ( version == '12.2(2)XK' ) flag++;
if ( version == '12.2(2)XK1' ) flag++;
if ( version == '12.2(2)XK2' ) flag++;
if ( version == '12.2(2)XK3' ) flag++;
if ( version == '12.2(2)XQ' ) flag++;
if ( version == '12.2(2)XQ1' ) flag++;
if ( version == '12.2(2)XT' ) flag++;
if ( version == '12.2(2)XT2' ) flag++;
if ( version == '12.2(2)XT3' ) flag++;
if ( version == '12.2(2)XU' ) flag++;
if ( version == '12.2(2)YC' ) flag++;
if ( version == '12.2(2)YC1' ) flag++;
if ( version == '12.2(2)YC2' ) flag++;
if ( version == '12.2(2)YC3' ) flag++;
if ( version == '12.2(2)YC4' ) flag++;
if ( version == '12.2(25)EW' ) flag++;
if ( version == '12.2(25)EWA' ) flag++;
if ( version == '12.2(25)EWA1' ) flag++;
if ( version == '12.2(25)EY' ) flag++;
if ( version == '12.2(25)EY1' ) flag++;
if ( version == '12.2(25)EZ' ) flag++;
if ( version == '12.2(25)EZ1' ) flag++;
if ( version == '12.2(25)SE' ) flag++;
if ( version == '12.2(25)SEA' ) flag++;
if ( version == '12.2(25)SEB' ) flag++;
if ( version == '12.2(25)SEB1' ) flag++;
if ( version == '12.2(30)S' ) flag++;
if ( version == '12.2(30)S1' ) flag++;
if ( version == '12.2(4)B' ) flag++;
if ( version == '12.2(4)B1' ) flag++;
if ( version == '12.2(4)B2' ) flag++;
if ( version == '12.2(4)B3' ) flag++;
if ( version == '12.2(4)B4' ) flag++;
if ( version == '12.2(4)B5' ) flag++;
if ( version == '12.2(4)B6' ) flag++;
if ( version == '12.2(4)B7' ) flag++;
if ( version == '12.2(4)B8' ) flag++;
if ( version == '12.2(4)BC1' ) flag++;
if ( version == '12.2(4)BC1a' ) flag++;
if ( version == '12.2(4)BC1b' ) flag++;
if ( version == '12.2(4)BW' ) flag++;
if ( version == '12.2(4)BW1' ) flag++;
if ( version == '12.2(4)BW1a' ) flag++;
if ( version == '12.2(4)BW2' ) flag++;
if ( version == '12.2(4)BZ1' ) flag++;
if ( version == '12.2(4)BZ2' ) flag++;
if ( version == '12.2(4)JA' ) flag++;
if ( version == '12.2(4)JA1' ) flag++;
if ( version == '12.2(4)MB1' ) flag++;
if ( version == '12.2(4)MB10' ) flag++;
if ( version == '12.2(4)MB11' ) flag++;
if ( version == '12.2(4)MB12' ) flag++;
if ( version == '12.2(4)MB13' ) flag++;
if ( version == '12.2(4)MB13a' ) flag++;
if ( version == '12.2(4)MB13b' ) flag++;
if ( version == '12.2(4)MB13c' ) flag++;
if ( version == '12.2(4)MB2' ) flag++;
if ( version == '12.2(4)MB3' ) flag++;
if ( version == '12.2(4)MB4' ) flag++;
if ( version == '12.2(4)MB5' ) flag++;
if ( version == '12.2(4)MB6' ) flag++;
if ( version == '12.2(4)MB7' ) flag++;
if ( version == '12.2(4)MB8' ) flag++;
if ( version == '12.2(4)MB9' ) flag++;
if ( version == '12.2(4)MB9a' ) flag++;
if ( version == '12.2(4)T' ) flag++;
if ( version == '12.2(4)T1' ) flag++;
if ( version == '12.2(4)T2' ) flag++;
if ( version == '12.2(4)T3' ) flag++;
if ( version == '12.2(4)T5' ) flag++;
if ( version == '12.2(4)T6' ) flag++;
if ( version == '12.2(4)T7' ) flag++;
if ( version == '12.2(4)XF' ) flag++;
if ( version == '12.2(4)XF1' ) flag++;
if ( version == '12.2(4)XL' ) flag++;
if ( version == '12.2(4)XL1' ) flag++;
if ( version == '12.2(4)XL2' ) flag++;
if ( version == '12.2(4)XL3' ) flag++;
if ( version == '12.2(4)XL4' ) flag++;
if ( version == '12.2(4)XL5' ) flag++;
if ( version == '12.2(4)XL6' ) flag++;
if ( version == '12.2(4)XM' ) flag++;
if ( version == '12.2(4)XM1' ) flag++;
if ( version == '12.2(4)XM2' ) flag++;
if ( version == '12.2(4)XM3' ) flag++;
if ( version == '12.2(4)XM4' ) flag++;
if ( version == '12.2(4)XR' ) flag++;
if ( version == '12.2(4)XV' ) flag++;
if ( version == '12.2(4)XV1' ) flag++;
if ( version == '12.2(4)XV2' ) flag++;
if ( version == '12.2(4)XV3' ) flag++;
if ( version == '12.2(4)XV4' ) flag++;
if ( version == '12.2(4)XV4a' ) flag++;
if ( version == '12.2(4)XV5' ) flag++;
if ( version == '12.2(4)XW' ) flag++;
if ( version == '12.2(4)YA' ) flag++;
if ( version == '12.2(4)YA1' ) flag++;
if ( version == '12.2(4)YA10' ) flag++;
if ( version == '12.2(4)YA2' ) flag++;
if ( version == '12.2(4)YA3' ) flag++;
if ( version == '12.2(4)YA4' ) flag++;
if ( version == '12.2(4)YA5' ) flag++;
if ( version == '12.2(4)YA6' ) flag++;
if ( version == '12.2(4)YA7' ) flag++;
if ( version == '12.2(4)YA8' ) flag++;
if ( version == '12.2(4)YA9' ) flag++;
if ( version == '12.2(4)YB' ) flag++;
if ( version == '12.2(4)YF' ) flag++;
if ( version == '12.2(4)YG' ) flag++;
if ( version == '12.2(4)YH' ) flag++;
if ( version == '12.2(8)BC1' ) flag++;
if ( version == '12.2(8)BC2' ) flag++;
if ( version == '12.2(8)BC2a' ) flag++;
if ( version == '12.2(8)BY' ) flag++;
if ( version == '12.2(8)BY1' ) flag++;
if ( version == '12.2(8)BY2' ) flag++;
if ( version == '12.2(8)JA' ) flag++;
if ( version == '12.2(8)MC1' ) flag++;
if ( version == '12.2(8)MC2' ) flag++;
if ( version == '12.2(8)MC2a' ) flag++;
if ( version == '12.2(8)MC2b' ) flag++;
if ( version == '12.2(8)MC2c' ) flag++;
if ( version == '12.2(8)MC2d' ) flag++;
if ( version == '12.2(8)T' ) flag++;
if ( version == '12.2(8)T1' ) flag++;
if ( version == '12.2(8)T10' ) flag++;
if ( version == '12.2(8)T2' ) flag++;
if ( version == '12.2(8)T3' ) flag++;
if ( version == '12.2(8)T4' ) flag++;
if ( version == '12.2(8)T5' ) flag++;
if ( version == '12.2(8)T7' ) flag++;
if ( version == '12.2(8)T8' ) flag++;
if ( version == '12.2(8)YD' ) flag++;
if ( version == '12.2(8)YD1' ) flag++;
if ( version == '12.2(8)YD2' ) flag++;
if ( version == '12.2(8)YD3' ) flag++;
if ( version == '12.2(8)YJ' ) flag++;
if ( version == '12.2(8)YJ1' ) flag++;
if ( version == '12.2(8)YL' ) flag++;
if ( version == '12.2(8)YM' ) flag++;
if ( version == '12.2(8)YN' ) flag++;
if ( version == '12.2(8)YN1' ) flag++;
if ( version == '12.2(8)YW' ) flag++;
if ( version == '12.2(8)YW1' ) flag++;
if ( version == '12.2(8)YW2' ) flag++;
if ( version == '12.2(8)YW3' ) flag++;
if ( version == '12.2(8)YY' ) flag++;
if ( version == '12.2(8)YY1' ) flag++;
if ( version == '12.2(8)YY2' ) flag++;
if ( version == '12.2(8)YY3' ) flag++;
if ( version == '12.2(8)YY4' ) flag++;
if ( version == '12.2(8)ZB' ) flag++;
if ( version == '12.2(8)ZB1' ) flag++;
if ( version == '12.2(8)ZB2' ) flag++;
if ( version == '12.2(8)ZB3' ) flag++;
if ( version == '12.2(8)ZB4' ) flag++;
if ( version == '12.2(8)ZB4a' ) flag++;
if ( version == '12.2(8)ZB5' ) flag++;
if ( version == '12.2(8)ZB6' ) flag++;
if ( version == '12.2(8)ZB7' ) flag++;
if ( version == '12.2(8)ZB8' ) flag++;
if ( version == '12.3(1)' ) flag++;
if ( version == '12.3(1a)' ) flag++;
if ( version == '12.3(1a)B' ) flag++;
if ( version == '12.3(1a)BW' ) flag++;
if ( version == '12.3(2)JA' ) flag++;
if ( version == '12.3(2)JA1' ) flag++;
if ( version == '12.3(2)JA2' ) flag++;
if ( version == '12.3(2)JA5' ) flag++;
if ( version == '12.3(2)T' ) flag++;
if ( version == '12.3(2)T1' ) flag++;
if ( version == '12.3(2)T2' ) flag++;
if ( version == '12.3(2)T3' ) flag++;
if ( version == '12.3(2)T4' ) flag++;
if ( version == '12.3(2)T5' ) flag++;
if ( version == '12.3(2)T6' ) flag++;
if ( version == '12.3(2)T7' ) flag++;
if ( version == '12.3(2)T8' ) flag++;
if ( version == '12.3(2)T9' ) flag++;
if ( version == '12.3(2)XA' ) flag++;
if ( version == '12.3(2)XA1' ) flag++;
if ( version == '12.3(2)XA2' ) flag++;
if ( version == '12.3(2)XA3' ) flag++;
if ( version == '12.3(2)XA4' ) flag++;
if ( version == '12.3(2)XB' ) flag++;
if ( version == '12.3(2)XB1' ) flag++;
if ( version == '12.3(2)XB3' ) flag++;
if ( version == '12.3(2)XC' ) flag++;
if ( version == '12.3(2)XC1' ) flag++;
if ( version == '12.3(2)XC2' ) flag++;
if ( version == '12.3(2)XC3' ) flag++;
if ( version == '12.3(2)XE' ) flag++;
if ( version == '12.3(2)XE1' ) flag++;
if ( version == '12.3(2)XE2' ) flag++;
if ( version == '12.3(2)XE3' ) flag++;
if ( version == '12.3(2)XF' ) flag++;
if ( version == '12.3(2)XZ' ) flag++;
if ( version == '12.3(2)XZ1' ) flag++;
if ( version == '12.3(2)XZ2' ) flag++;
if ( version == '12.3(3)' ) flag++;
if ( version == '12.3(3)B' ) flag++;
if ( version == '12.3(3)B1' ) flag++;
if ( version == '12.3(3a)' ) flag++;
if ( version == '12.3(3b)' ) flag++;
if ( version == '12.3(3c)' ) flag++;
if ( version == '12.3(3e)' ) flag++;
if ( version == '12.3(3f)' ) flag++;
if ( version == '12.3(3g)' ) flag++;
if ( version == '12.3(3h)' ) flag++;
if ( version == '12.3(4)JA' ) flag++;
if ( version == '12.3(4)JA1' ) flag++;
if ( version == '12.3(4)T' ) flag++;
if ( version == '12.3(4)T1' ) flag++;
if ( version == '12.3(4)T10' ) flag++;
if ( version == '12.3(4)T11' ) flag++;
if ( version == '12.3(4)T2' ) flag++;
if ( version == '12.3(4)T2a' ) flag++;
if ( version == '12.3(4)T3' ) flag++;
if ( version == '12.3(4)T4' ) flag++;
if ( version == '12.3(4)T6' ) flag++;
if ( version == '12.3(4)T7' ) flag++;
if ( version == '12.3(4)T8' ) flag++;
if ( version == '12.3(4)T9' ) flag++;
if ( version == '12.3(4)XD' ) flag++;
if ( version == '12.3(4)XD1' ) flag++;
if ( version == '12.3(4)XD2' ) flag++;
if ( version == '12.3(4)XD3' ) flag++;
if ( version == '12.3(4)XD4' ) flag++;
if ( version == '12.3(4)XG' ) flag++;
if ( version == '12.3(4)XG1' ) flag++;
if ( version == '12.3(4)XG2' ) flag++;
if ( version == '12.3(4)XG3' ) flag++;
if ( version == '12.3(4)XG4' ) flag++;
if ( version == '12.3(4)XK' ) flag++;
if ( version == '12.3(4)XK1' ) flag++;
if ( version == '12.3(4)XK2' ) flag++;
if ( version == '12.3(4)XK3' ) flag++;
if ( version == '12.3(4)XQ' ) flag++;
if ( version == '12.3(4)XQ1' ) flag++;
if ( version == '12.3(5)' ) flag++;
if ( version == '12.3(5a)' ) flag++;
if ( version == '12.3(5a)B' ) flag++;
if ( version == '12.3(5a)B1' ) flag++;
if ( version == '12.3(5a)B2' ) flag++;
if ( version == '12.3(5a)B3' ) flag++;
if ( version == '12.3(5a)B4' ) flag++;
if ( version == '12.3(5a)B5' ) flag++;
if ( version == '12.3(5b)' ) flag++;
if ( version == '12.3(5c)' ) flag++;
if ( version == '12.3(5d)' ) flag++;
if ( version == '12.3(5e)' ) flag++;
if ( version == '12.3(6)' ) flag++;
if ( version == '12.3(6a)' ) flag++;
if ( version == '12.3(6b)' ) flag++;
if ( version == '12.3(6c)' ) flag++;
if ( version == '12.3(6e)' ) flag++;
if ( version == '12.3(7)T' ) flag++;
if ( version == '12.3(7)T1' ) flag++;
if ( version == '12.3(7)T10' ) flag++;
if ( version == '12.3(7)T2' ) flag++;
if ( version == '12.3(7)T3' ) flag++;
if ( version == '12.3(7)T4' ) flag++;
if ( version == '12.3(7)T6' ) flag++;
if ( version == '12.3(7)T7' ) flag++;
if ( version == '12.3(7)T8' ) flag++;
if ( version == '12.3(7)T9' ) flag++;
if ( version == '12.3(7)XI1' ) flag++;
if ( version == '12.3(7)XI1b' ) flag++;
if ( version == '12.3(7)XI1c' ) flag++;
if ( version == '12.3(7)XI2' ) flag++;
if ( version == '12.3(7)XI2a' ) flag++;
if ( version == '12.3(7)XI3' ) flag++;
if ( version == '12.3(7)XI4' ) flag++;
if ( version == '12.3(7)XI5' ) flag++;
if ( version == '12.3(7)XJ' ) flag++;
if ( version == '12.3(7)XJ1' ) flag++;
if ( version == '12.3(7)XJ2' ) flag++;
if ( version == '12.3(7)XR' ) flag++;
if ( version == '12.3(7)XR2' ) flag++;
if ( version == '12.3(7)XR3' ) flag++;
if ( version == '12.3(7)XR4' ) flag++;
if ( version == '12.3(7)XS' ) flag++;
if ( version == '12.3(7)XS1' ) flag++;
if ( version == '12.3(7)XS2' ) flag++;
if ( version == '12.3(8)T' ) flag++;
if ( version == '12.3(8)T1' ) flag++;
if ( version == '12.3(8)T3' ) flag++;
if ( version == '12.3(8)XU' ) flag++;
if ( version == '12.3(8)XU1' ) flag++;
if ( version == '12.3(8)XU2' ) flag++;
if ( version == '12.3(8)XU3' ) flag++;
if ( version == '12.3(8)XU4' ) flag++;
if ( version == '12.3(8)XU5' ) flag++;
if ( version == '12.3(8)XW' ) flag++;
if ( version == '12.3(8)XW1' ) flag++;
if ( version == '12.3(8)XW2' ) flag++;
if ( version == '12.3(8)XW3' ) flag++;
if ( version == '12.3(8)XX' ) flag++;
if ( version == '12.3(8)XX1' ) flag++;
if ( version == '12.3(8)XY' ) flag++;
if ( version == '12.3(8)XY1' ) flag++;
if ( version == '12.3(8)XY2' ) flag++;
if ( version == '12.3(8)XY3' ) flag++;
if ( version == '12.3(8)XY4' ) flag++;
if ( version == '12.3(8)YA' ) flag++;
if ( version == '12.3(8)YA1' ) flag++;
if ( version == '12.3(9)' ) flag++;
if ( version == '12.3(9a)' ) flag++;
if ( version == '12.3(9a)BC' ) flag++;
if ( version == '12.3(9a)BC1' ) flag++;
if ( version == '12.3(9a)BC2' ) flag++;
if ( version == '12.3(9a)BC3' ) flag++;
if ( version == '12.3(9a)BC4' ) flag++;
if ( version == '12.3(9a)BC5' ) flag++;
if ( version == '12.3(9a)BC6' ) flag++;
if ( version == '12.3(9b)' ) flag++;
if ( version == '12.3(9c)' ) flag++;
if ( version == '12.3(9d)' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"aaa authentication login [^\r\n]+ group radius none", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"aaa authentication ppp [^\r\n]+ group radius none", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"aaa authentication login [^\r\n]'+ group radius local none", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"aaa authentication ppp [^\r\n]+ group radius local none", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

