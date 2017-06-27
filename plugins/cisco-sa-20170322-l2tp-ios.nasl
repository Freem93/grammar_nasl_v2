#TRUSTED 1a9c72caa9579d8ecae866a5089e5b6d1a539a0206a2ce387ab01809f8b08ff88493611e3eaad1b8eaf4a7044052725f84d7fac38099f3b7d01d6f678eeda6ae8e5e5974870810e4a0ac2110df0f5cf9cb65d6eb253f3fc3dee1a5569b2253ecacaa1149fd79e5214dea05853a589b70252497116a0dd20da3c27c8ab5f393ceb43cd147e5d5a3ac1600e8ec575d228683a308bd9f1bd409ee5c777be71cf71ff4f5eb9b25d4175a84729f42148b4d3fe33d3958142171b06919111b2b6440fc5dc3afeb7c48c6b30dd9e963b6815a38bae18ed849532033cc79648adc022858e944051775bbb969b4b06c04632833de27a8664be5f34d4f3bf69c3b62eef0703a1865d409e02f91ce6320eb5a687975d613ff6d386f7f89016c58ed5096bc4ad3595ddce26d048fa6f11ae8b7047f3c25a33388a023bc3fe0aedb0130e9765df1507eff6bfad88b28003888e91dbad4bdfc088f7cd3a87cd6566b64c589fd9949dc0b19d34e100b8eb53cfb5dc93f357ee1629eb367e3f70601b1c308ba7146fdc7a7447eae2bc70195f5d4e7d629ba5f4ea9b2248acfb4a6ef2c02626605681965b786fd4ad9526278577ce73c81a94bb238d016ed0910f4f6fb2c94386230326461dc5f9f1d439dc683910c14d75723cfcf2accb27936772ad3a26dc5e8c27090f20a7cfec16248c7868092a673ef6c15d1affd365963007756b0bf965ad2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99028);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3857");
  script_bugtraq_id(97010);
  script_osvdb_id(154191);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82078");
  script_xref(name:"IAVA", value:"2017-A-0082");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-l2tp");

  script_name(english:"Cisco IOS L2TP Parsing DoS (cisco-sa-20170322-l2tp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in its Layer 2 Tunneling Protocol (L2TP) parsing function due to
insufficient validation of L2TP packets. An unauthenticated, remote
attacker can exploit this issue, via a specially crafted L2TP packet,
to cause the device to reload.

Note that this issue only affects devices if the L2TP feature is
enabled and the device is configured as an L2TP Version 2 (L2TPv2) or
L2TP Version 3 (L2TPv3) endpoint. By default, the L2TP feature is not
enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4fc7ea8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82078");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy82078.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln versions
if (
  ver == "12.0(33)S" ||
  ver == "12.0(33)S1" ||
  ver == "12.0(33)S10" ||
  ver == "12.0(33)S11" ||
  ver == "12.0(33)S2" ||
  ver == "12.0(33)S3" ||
  ver == "12.0(33)S4" ||
  ver == "12.0(33)S5" ||
  ver == "12.0(33)S6" ||
  ver == "12.0(33)S7" ||
  ver == "12.0(33)S8" ||
  ver == "12.0(33)S9" ||
  ver == "12.2(33)CX" ||
  ver == "12.2(33)CY" ||
  ver == "12.2(33)CY1" ||
  ver == "12.2(33)IRA" ||
  ver == "12.2(33)IRB" ||
  ver == "12.2(33)IRC" ||
  ver == "12.2(33)IRD" ||
  ver == "12.2(33)IRE" ||
  ver == "12.2(33)IRE1" ||
  ver == "12.2(33)IRE2" ||
  ver == "12.2(33)IRF" ||
  ver == "12.2(33)IRG" ||
  ver == "12.2(33)IRG1" ||
  ver == "12.2(33)IRH" ||
  ver == "12.2(33)IRH1" ||
  ver == "12.2(33)IRI" ||
  ver == "12.2(33)MRA" ||
  ver == "12.2(33)MRB" ||
  ver == "12.2(33)MRB1" ||
  ver == "12.2(33)MRB2" ||
  ver == "12.2(33)MRB3" ||
  ver == "12.2(33)MRB4" ||
  ver == "12.2(33)MRB5" ||
  ver == "12.2(33)MRB6" ||
  ver == "12.2(33)SB" ||
  ver == "12.2(33)SB1" ||
  ver == "12.2(33)SB10" ||
  ver == "12.2(33)SB11" ||
  ver == "12.2(33)SB12" ||
  ver == "12.2(33)SB13" ||
  ver == "12.2(33)SB14" ||
  ver == "12.2(33)SB15" ||
  ver == "12.2(33)SB16" ||
  ver == "12.2(33)SB17" ||
  ver == "12.2(33)SB2" ||
  ver == "12.2(33)SB3" ||
  ver == "12.2(33)SB4" ||
  ver == "12.2(33)SB5" ||
  ver == "12.2(33)SB6" ||
  ver == "12.2(33)SB7" ||
  ver == "12.2(33)SB8" ||
  ver == "12.2(33)SB9" ||
  ver == "12.2(33)SCA" ||
  ver == "12.2(33)SCA1" ||
  ver == "12.2(33)SCA2" ||
  ver == "12.2(33)SCB" ||
  ver == "12.2(33)SCB1" ||
  ver == "12.2(33)SCB10" ||
  ver == "12.2(33)SCB11" ||
  ver == "12.2(33)SCB2" ||
  ver == "12.2(33)SCB3" ||
  ver == "12.2(33)SCB4" ||
  ver == "12.2(33)SCB5" ||
  ver == "12.2(33)SCB6" ||
  ver == "12.2(33)SCB7" ||
  ver == "12.2(33)SCB8" ||
  ver == "12.2(33)SCB9" ||
  ver == "12.2(33)SCC" ||
  ver == "12.2(33)SCC1" ||
  ver == "12.2(33)SCC2" ||
  ver == "12.2(33)SCC3" ||
  ver == "12.2(33)SCC4" ||
  ver == "12.2(33)SCC5" ||
  ver == "12.2(33)SCC6" ||
  ver == "12.2(33)SCC7" ||
  ver == "12.2(33)SCD" ||
  ver == "12.2(33)SCD1" ||
  ver == "12.2(33)SCD2" ||
  ver == "12.2(33)SCD3" ||
  ver == "12.2(33)SCD4" ||
  ver == "12.2(33)SCD5" ||
  ver == "12.2(33)SCD6" ||
  ver == "12.2(33)SCD7" ||
  ver == "12.2(33)SCD8" ||
  ver == "12.2(33)SCE" ||
  ver == "12.2(33)SCE1" ||
  ver == "12.2(33)SCE2" ||
  ver == "12.2(33)SCE3" ||
  ver == "12.2(33)SCE4" ||
  ver == "12.2(33)SCE5" ||
  ver == "12.2(33)SCE6" ||
  ver == "12.2(33)SCF" ||
  ver == "12.2(33)SCF1" ||
  ver == "12.2(33)SCF2" ||
  ver == "12.2(33)SCF3" ||
  ver == "12.2(33)SCF4" ||
  ver == "12.2(33)SCF5" ||
  ver == "12.2(33)SCG" ||
  ver == "12.2(33)SCG1" ||
  ver == "12.2(33)SCG2" ||
  ver == "12.2(33)SCG3" ||
  ver == "12.2(33)SCG4" ||
  ver == "12.2(33)SCG5" ||
  ver == "12.2(33)SCG6" ||
  ver == "12.2(33)SCG7" ||
  ver == "12.2(33)SCH" ||
  ver == "12.2(33)SCH0a" ||
  ver == "12.2(33)SCH1" ||
  ver == "12.2(33)SCH2" ||
  ver == "12.2(33)SCH2a" ||
  ver == "12.2(33)SCH3" ||
  ver == "12.2(33)SCH4" ||
  ver == "12.2(33)SCH5" ||
  ver == "12.2(33)SCH6" ||
  ver == "12.2(33)SCI" ||
  ver == "12.2(33)SCI1" ||
  ver == "12.2(33)SCI1a" ||
  ver == "12.2(33)SCI2" ||
  ver == "12.2(33)SCI2a" ||
  ver == "12.2(33)SCI3" ||
  ver == "12.2(33)SCJ" ||
  ver == "12.2(33)SCJ1a" ||
  ver == "12.2(33)SCJ2" ||
  ver == "12.2(33)SCJ2a" ||
  ver == "12.2(33)SRB" ||
  ver == "12.2(33)SRC" ||
  ver == "12.2(33)SRC1" ||
  ver == "12.2(33)SRC2" ||
  ver == "12.2(33)SRC3" ||
  ver == "12.2(33)SRC4" ||
  ver == "12.2(33)SRC5" ||
  ver == "12.2(33)SRC6" ||
  ver == "12.2(33)SRD" ||
  ver == "12.2(33)SRD1" ||
  ver == "12.2(33)SRD2" ||
  ver == "12.2(33)SRD2a" ||
  ver == "12.2(33)SRD3" ||
  ver == "12.2(33)SRD4" ||
  ver == "12.2(33)SRD5" ||
  ver == "12.2(33)SRD6" ||
  ver == "12.2(33)SRD7" ||
  ver == "12.2(33)SRD8" ||
  ver == "12.2(33)SRE" ||
  ver == "12.2(33)SRE0a" ||
  ver == "12.2(33)SRE1" ||
  ver == "12.2(33)SRE10" ||
  ver == "12.2(33)SRE11" ||
  ver == "12.2(33)SRE12" ||
  ver == "12.2(33)SRE13" ||
  ver == "12.2(33)SRE14" ||
  ver == "12.2(33)SRE15" ||
  ver == "12.2(33)SRE2" ||
  ver == "12.2(33)SRE3" ||
  ver == "12.2(33)SRE4" ||
  ver == "12.2(33)SRE5" ||
  ver == "12.2(33)SRE6" ||
  ver == "12.2(33)SRE7" ||
  ver == "12.2(33)SRE7a" ||
  ver == "12.2(33)SRE8" ||
  ver == "12.2(33)SRE9" ||
  ver == "12.2(33)SRE9a" ||
  ver == "12.2(33)XN1" ||
  ver == "12.2(37)SE" ||
  ver == "12.2(37)SE1" ||
  ver == "12.2(37)SG1" ||
  ver == "12.2(40)SE" ||
  ver == "12.2(44)SE" ||
  ver == "12.2(44)SE1" ||
  ver == "12.2(44)SE2" ||
  ver == "12.2(44)SE3" ||
  ver == "12.2(44)SE5" ||
  ver == "12.2(44)SE6" ||
  ver == "12.2(46)SE" ||
  ver == "12.2(50)SE" ||
  ver == "12.2(50)SE1" ||
  ver == "12.2(50)SE3" ||
  ver == "12.2(50)SE4" ||
  ver == "12.2(50)SE5" ||
  ver == "12.2(50)SQ" ||
  ver == "12.2(50)SQ1" ||
  ver == "12.2(50)SQ2" ||
  ver == "12.2(50)SQ3" ||
  ver == "12.2(50)SQ4" ||
  ver == "12.2(50)SQ5" ||
  ver == "12.2(50)SQ6" ||
  ver == "12.2(50)SQ7" ||
  ver == "12.2(52)SE" ||
  ver == "12.2(54)SE" ||
  ver == "12.2(55)SE" ||
  ver == "12.2(55)SE10" ||
  ver == "12.2(55)SE11" ||
  ver == "12.2(55)SE3" ||
  ver == "12.2(55)SE4" ||
  ver == "12.2(55)SE5" ||
  ver == "12.2(55)SE6" ||
  ver == "12.2(55)SE7" ||
  ver == "12.2(55)SE8" ||
  ver == "12.2(55)SE9" ||
  ver == "12.2(58)EX" ||
  ver == "12.2(58)EZ" ||
  ver == "12.2(58)SE2" ||
  ver == "12.2(60)EZ4" ||
  ver == "12.2(60)EZ5" ||
  ver == "12.4(11)MR" ||
  ver == "12.4(11)SW" ||
  ver == "12.4(11)SW1" ||
  ver == "12.4(11)SW2" ||
  ver == "12.4(11)SW3" ||
  ver == "12.4(11)T" ||
  ver == "12.4(11)T1" ||
  ver == "12.4(11)T2" ||
  ver == "12.4(11)T3" ||
  ver == "12.4(11)T4" ||
  ver == "12.4(11)XJ" ||
  ver == "12.4(11)XJ2" ||
  ver == "12.4(11)XJ3" ||
  ver == "12.4(11)XJ4" ||
  ver == "12.4(11)XV" ||
  ver == "12.4(11)XV1" ||
  ver == "12.4(11)XW" ||
  ver == "12.4(11)XW1" ||
  ver == "12.4(11)XW10" ||
  ver == "12.4(11)XW2" ||
  ver == "12.4(11)XW3" ||
  ver == "12.4(11)XW4" ||
  ver == "12.4(11)XW5" ||
  ver == "12.4(11)XW6" ||
  ver == "12.4(11)XW7" ||
  ver == "12.4(11)XW8" ||
  ver == "12.4(11)XW9" ||
  ver == "12.4(12)MR" ||
  ver == "12.4(12)MR1" ||
  ver == "12.4(12)MR2" ||
  ver == "12.4(14)XK" ||
  ver == "12.4(15)SW" ||
  ver == "12.4(15)SW1" ||
  ver == "12.4(15)SW2" ||
  ver == "12.4(15)SW3" ||
  ver == "12.4(15)SW4" ||
  ver == "12.4(15)SW5" ||
  ver == "12.4(15)SW6" ||
  ver == "12.4(15)SW7" ||
  ver == "12.4(15)SW8" ||
  ver == "12.4(15)SW8a" ||
  ver == "12.4(15)SW9" ||
  ver == "12.4(15)T" ||
  ver == "12.4(15)T1" ||
  ver == "12.4(15)T10" ||
  ver == "12.4(15)T11" ||
  ver == "12.4(15)T12" ||
  ver == "12.4(15)T13" ||
  ver == "12.4(15)T14" ||
  ver == "12.4(15)T15" ||
  ver == "12.4(15)T16" ||
  ver == "12.4(15)T17" ||
  ver == "12.4(15)T2" ||
  ver == "12.4(15)T3" ||
  ver == "12.4(15)T4" ||
  ver == "12.4(15)T5" ||
  ver == "12.4(15)T6" ||
  ver == "12.4(15)T7" ||
  ver == "12.4(15)T8" ||
  ver == "12.4(15)T9" ||
  ver == "12.4(15)XF" ||
  ver == "12.4(15)XL" ||
  ver == "12.4(15)XL1" ||
  ver == "12.4(15)XL2" ||
  ver == "12.4(15)XL3" ||
  ver == "12.4(15)XL4" ||
  ver == "12.4(15)XL5" ||
  ver == "12.4(15)XM" ||
  ver == "12.4(15)XM1" ||
  ver == "12.4(15)XM2" ||
  ver == "12.4(15)XM3" ||
  ver == "12.4(15)XN" ||
  ver == "12.4(15)XQ" ||
  ver == "12.4(15)XQ1" ||
  ver == "12.4(15)XQ2" ||
  ver == "12.4(15)XQ2a" ||
  ver == "12.4(15)XQ2b" ||
  ver == "12.4(15)XQ3" ||
  ver == "12.4(15)XQ4" ||
  ver == "12.4(15)XQ5" ||
  ver == "12.4(15)XQ6" ||
  ver == "12.4(15)XQ7" ||
  ver == "12.4(15)XQ8" ||
  ver == "12.4(15)XR" ||
  ver == "12.4(15)XR1" ||
  ver == "12.4(15)XR10" ||
  ver == "12.4(15)XR2" ||
  ver == "12.4(15)XR3" ||
  ver == "12.4(15)XR4" ||
  ver == "12.4(15)XR5" ||
  ver == "12.4(15)XR6" ||
  ver == "12.4(15)XR7" ||
  ver == "12.4(15)XR8" ||
  ver == "12.4(15)XR9" ||
  ver == "12.4(15)XY" ||
  ver == "12.4(15)XY1" ||
  ver == "12.4(15)XY2" ||
  ver == "12.4(15)XY3" ||
  ver == "12.4(15)XY4" ||
  ver == "12.4(15)XY5" ||
  ver == "12.4(15)XZ" ||
  ver == "12.4(15)XZ1" ||
  ver == "12.4(15)XZ2" ||
  ver == "12.4(16)MR" ||
  ver == "12.4(16)MR1" ||
  ver == "12.4(16)MR2" ||
  ver == "12.4(19)MR" ||
  ver == "12.4(19)MR1" ||
  ver == "12.4(19)MR2" ||
  ver == "12.4(19)MR3" ||
  ver == "12.4(20)MR" ||
  ver == "12.4(20)MR2" ||
  ver == "12.4(20)MRB" ||
  ver == "12.4(20)MRB1" ||
  ver == "12.4(20)T" ||
  ver == "12.4(20)T1" ||
  ver == "12.4(20)T2" ||
  ver == "12.4(20)T3" ||
  ver == "12.4(20)T4" ||
  ver == "12.4(20)T5" ||
  ver == "12.4(20)T6" ||
  ver == "12.4(20)YA" ||
  ver == "12.4(20)YA1" ||
  ver == "12.4(20)YA2" ||
  ver == "12.4(20)YA3" ||
  ver == "12.4(22)GC1" ||
  ver == "12.4(22)T" ||
  ver == "12.4(22)T1" ||
  ver == "12.4(22)T2" ||
  ver == "12.4(22)T3" ||
  ver == "12.4(22)T4" ||
  ver == "12.4(22)T5" ||
  ver == "12.4(22)XR1" ||
  ver == "12.4(22)XR10" ||
  ver == "12.4(22)XR11" ||
  ver == "12.4(22)XR12" ||
  ver == "12.4(22)XR2" ||
  ver == "12.4(22)XR3" ||
  ver == "12.4(22)XR4" ||
  ver == "12.4(22)XR5" ||
  ver == "12.4(22)XR6" ||
  ver == "12.4(22)XR7" ||
  ver == "12.4(22)XR8" ||
  ver == "12.4(22)XR9" ||
  ver == "12.4(22)YB" ||
  ver == "12.4(22)YB1" ||
  ver == "12.4(22)YB2" ||
  ver == "12.4(22)YB3" ||
  ver == "12.4(22)YB4" ||
  ver == "12.4(22)YB5" ||
  ver == "12.4(22)YB6" ||
  ver == "12.4(22)YB7" ||
  ver == "12.4(22)YB8" ||
  ver == "12.4(22)YD" ||
  ver == "12.4(22)YD1" ||
  ver == "12.4(22)YD2" ||
  ver == "12.4(22)YD3" ||
  ver == "12.4(22)YD4" ||
  ver == "12.4(22)YE" ||
  ver == "12.4(22)YE1" ||
  ver == "12.4(22)YE2" ||
  ver == "12.4(22)YE3" ||
  ver == "12.4(22)YE4" ||
  ver == "12.4(22)YE5" ||
  ver == "12.4(22)YE6" ||
  ver == "12.4(24)GC1" ||
  ver == "12.4(24)GC3" ||
  ver == "12.4(24)GC3a" ||
  ver == "12.4(24)GC4" ||
  ver == "12.4(24)GC5" ||
  ver == "12.4(24)T" ||
  ver == "12.4(24)T1" ||
  ver == "12.4(24)T2" ||
  ver == "12.4(24)T3" ||
  ver == "12.4(24)T3e" ||
  ver == "12.4(24)T3f" ||
  ver == "12.4(24)T4" ||
  ver == "12.4(24)T4a" ||
  ver == "12.4(24)T4b" ||
  ver == "12.4(24)T4c" ||
  ver == "12.4(24)T4d" ||
  ver == "12.4(24)T4e" ||
  ver == "12.4(24)T4f" ||
  ver == "12.4(24)T4l" ||
  ver == "12.4(24)T5" ||
  ver == "12.4(24)T6" ||
  ver == "12.4(24)T7" ||
  ver == "12.4(24)T8" ||
  ver == "12.4(24)YE" ||
  ver == "12.4(24)YE1" ||
  ver == "12.4(24)YE2" ||
  ver == "12.4(24)YE3" ||
  ver == "12.4(24)YE3a" ||
  ver == "12.4(24)YE3b" ||
  ver == "12.4(24)YE3c" ||
  ver == "12.4(24)YE3d" ||
  ver == "12.4(24)YE3e" ||
  ver == "12.4(24)YE4" ||
  ver == "12.4(24)YE5" ||
  ver == "12.4(24)YE6" ||
  ver == "12.4(24)YE7" ||
  ver == "12.4(24)YG1" ||
  ver == "12.4(24)YG2" ||
  ver == "12.4(24)YG3" ||
  ver == "12.4(24)YG4" ||
  ver == "15.0(1)EX" ||
  ver == "15.0(1)M" ||
  ver == "15.0(1)M1" ||
  ver == "15.0(1)M10" ||
  ver == "15.0(1)M2" ||
  ver == "15.0(1)M3" ||
  ver == "15.0(1)M4" ||
  ver == "15.0(1)M5" ||
  ver == "15.0(1)M6" ||
  ver == "15.0(1)M7" ||
  ver == "15.0(1)M8" ||
  ver == "15.0(1)M9" ||
  ver == "15.0(1)MR" ||
  ver == "15.0(1)S" ||
  ver == "15.0(1)S1" ||
  ver == "15.0(1)S2" ||
  ver == "15.0(1)S3a" ||
  ver == "15.0(1)S4" ||
  ver == "15.0(1)S4a" ||
  ver == "15.0(1)S5" ||
  ver == "15.0(1)S6" ||
  ver == "15.0(1)XA" ||
  ver == "15.0(1)XA1" ||
  ver == "15.0(1)XA2" ||
  ver == "15.0(1)XA3" ||
  ver == "15.0(1)XA4" ||
  ver == "15.0(1)XA5" ||
  ver == "15.0(2)MR" ||
  ver == "15.0(2)SQD" ||
  ver == "15.0(2)SQD1" ||
  ver == "15.0(2)SQD2" ||
  ver == "15.0(2)SQD3" ||
  ver == "15.0(2)SQD4" ||
  ver == "15.1(1)MR" ||
  ver == "15.1(1)MR1" ||
  ver == "15.1(1)MR2" ||
  ver == "15.1(1)MR3" ||
  ver == "15.1(1)MR4" ||
  ver == "15.1(1)S" ||
  ver == "15.1(1)S1" ||
  ver == "15.1(1)S2" ||
  ver == "15.1(1)T" ||
  ver == "15.1(1)T1" ||
  ver == "15.1(1)T2" ||
  ver == "15.1(1)T3" ||
  ver == "15.1(1)T4" ||
  ver == "15.1(1)T5" ||
  ver == "15.1(1)XB" ||
  ver == "15.1(2)EY" ||
  ver == "15.1(2)EY1a" ||
  ver == "15.1(2)EY2" ||
  ver == "15.1(2)EY2a" ||
  ver == "15.1(2)EY3" ||
  ver == "15.1(2)EY4" ||
  ver == "15.1(2)GC" ||
  ver == "15.1(2)GC1" ||
  ver == "15.1(2)GC2" ||
  ver == "15.1(2)S" ||
  ver == "15.1(2)S1" ||
  ver == "15.1(2)S2" ||
  ver == "15.1(2)SNG" ||
  ver == "15.1(2)SNH" ||
  ver == "15.1(2)SNI" ||
  ver == "15.1(2)SNI1" ||
  ver == "15.1(2)SY" ||
  ver == "15.1(2)T" ||
  ver == "15.1(2)T0a" ||
  ver == "15.1(2)T1" ||
  ver == "15.1(2)T2" ||
  ver == "15.1(2)T2a" ||
  ver == "15.1(2)T3" ||
  ver == "15.1(2)T4" ||
  ver == "15.1(2)T5" ||
  ver == "15.1(3)MR" ||
  ver == "15.1(3)MRA" ||
  ver == "15.1(3)MRA1" ||
  ver == "15.1(3)MRA2" ||
  ver == "15.1(3)S" ||
  ver == "15.1(3)S0a" ||
  ver == "15.1(3)S1" ||
  ver == "15.1(3)S2" ||
  ver == "15.1(3)S3" ||
  ver == "15.1(3)S4" ||
  ver == "15.1(3)S5" ||
  ver == "15.1(3)S5a" ||
  ver == "15.1(3)S6" ||
  ver == "15.1(3)T" ||
  ver == "15.1(3)T1" ||
  ver == "15.1(3)T2" ||
  ver == "15.1(3)T3" ||
  ver == "15.1(3)T4" ||
  ver == "15.1(4)GC" ||
  ver == "15.1(4)GC1" ||
  ver == "15.1(4)GC2" ||
  ver == "15.1(4)M" ||
  ver == "15.1(4)M1" ||
  ver == "15.1(4)M10" ||
  ver == "15.1(4)M2" ||
  ver == "15.1(4)M3" ||
  ver == "15.1(4)M3a" ||
  ver == "15.1(4)M4" ||
  ver == "15.1(4)M5" ||
  ver == "15.1(4)M6" ||
  ver == "15.1(4)M7" ||
  ver == "15.1(4)M8" ||
  ver == "15.1(4)M9" ||
  ver == "15.2(1)GC" ||
  ver == "15.2(1)GC1" ||
  ver == "15.2(1)GC2" ||
  ver == "15.2(1)S" ||
  ver == "15.2(1)S1" ||
  ver == "15.2(1)S2" ||
  ver == "15.2(1)T" ||
  ver == "15.2(1)T1" ||
  ver == "15.2(1)T2" ||
  ver == "15.2(1)T3" ||
  ver == "15.2(1)T3a" ||
  ver == "15.2(1)T4" ||
  ver == "15.2(2)GC" ||
  ver == "15.2(2)JB" ||
  ver == "15.2(2)JB2" ||
  ver == "15.2(2)JB3" ||
  ver == "15.2(2)JB4" ||
  ver == "15.2(2)JB5" ||
  ver == "15.2(2)JB6" ||
  ver == "15.2(2)S" ||
  ver == "15.2(2)S0a" ||
  ver == "15.2(2)S0c" ||
  ver == "15.2(2)S1" ||
  ver == "15.2(2)S2" ||
  ver == "15.2(2)SNG" ||
  ver == "15.2(2)SNH1" ||
  ver == "15.2(2)SNI" ||
  ver == "15.2(2)T" ||
  ver == "15.2(2)T1" ||
  ver == "15.2(2)T2" ||
  ver == "15.2(2)T3" ||
  ver == "15.2(2)T4" ||
  ver == "15.2(3)GC" ||
  ver == "15.2(3)GC1" ||
  ver == "15.2(3)T" ||
  ver == "15.2(3)T1" ||
  ver == "15.2(3)T2" ||
  ver == "15.2(3)T3" ||
  ver == "15.2(3)T4" ||
  ver == "15.2(4)GC" ||
  ver == "15.2(4)GC1" ||
  ver == "15.2(4)GC2" ||
  ver == "15.2(4)GC3" ||
  ver == "15.2(4)JA" ||
  ver == "15.2(4)JA1" ||
  ver == "15.2(4)JB" ||
  ver == "15.2(4)JB1" ||
  ver == "15.2(4)JB2" ||
  ver == "15.2(4)JB3" ||
  ver == "15.2(4)JB3a" ||
  ver == "15.2(4)JB3b" ||
  ver == "15.2(4)JB3h" ||
  ver == "15.2(4)JB3s" ||
  ver == "15.2(4)JB4" ||
  ver == "15.2(4)JB5" ||
  ver == "15.2(4)JB50" ||
  ver == "15.2(4)JB5h" ||
  ver == "15.2(4)JB5m" ||
  ver == "15.2(4)JB6" ||
  ver == "15.2(4)JB7" ||
  ver == "15.2(4)JN" ||
  ver == "15.2(4)M" ||
  ver == "15.2(4)M1" ||
  ver == "15.2(4)M10" ||
  ver == "15.2(4)M11" ||
  ver == "15.2(4)M2" ||
  ver == "15.2(4)M3" ||
  ver == "15.2(4)M4" ||
  ver == "15.2(4)M5" ||
  ver == "15.2(4)M6" ||
  ver == "15.2(4)M6a" ||
  ver == "15.2(4)M7" ||
  ver == "15.2(4)M8" ||
  ver == "15.2(4)M9" ||
  ver == "15.2(4)S" ||
  ver == "15.2(4)S1" ||
  ver == "15.2(4)S2" ||
  ver == "15.2(4)S3" ||
  ver == "15.2(4)S3a" ||
  ver == "15.2(4)S4" ||
  ver == "15.2(4)S4a" ||
  ver == "15.2(4)S5" ||
  ver == "15.2(4)S6" ||
  ver == "15.2(4)S7" ||
  ver == "15.3(1)S" ||
  ver == "15.3(1)S1" ||
  ver == "15.3(1)S2" ||
  ver == "15.3(1)T" ||
  ver == "15.3(1)T1" ||
  ver == "15.3(1)T2" ||
  ver == "15.3(1)T3" ||
  ver == "15.3(1)T4" ||
  ver == "15.3(2)S" ||
  ver == "15.3(2)S1" ||
  ver == "15.3(2)S2" ||
  ver == "15.3(2)T" ||
  ver == "15.3(2)T1" ||
  ver == "15.3(2)T2" ||
  ver == "15.3(2)T3" ||
  ver == "15.3(2)T4" ||
  ver == "15.3(3)JA" ||
  ver == "15.3(3)JA1" ||
  ver == "15.3(3)JA10" ||
  ver == "15.3(3)JA1m" ||
  ver == "15.3(3)JA1n" ||
  ver == "15.3(3)JA4" ||
  ver == "15.3(3)JA5" ||
  ver == "15.3(3)JA6" ||
  ver == "15.3(3)JA7" ||
  ver == "15.3(3)JA77" ||
  ver == "15.3(3)JA8" ||
  ver == "15.3(3)JA9" ||
  ver == "15.3(3)JAA" ||
  ver == "15.3(3)JAB" ||
  ver == "15.3(3)JAX" ||
  ver == "15.3(3)JAX1" ||
  ver == "15.3(3)JAX2" ||
  ver == "15.3(3)JB" ||
  ver == "15.3(3)JB75" ||
  ver == "15.3(3)JBB" ||
  ver == "15.3(3)JBB1" ||
  ver == "15.3(3)JBB2" ||
  ver == "15.3(3)JBB4" ||
  ver == "15.3(3)JBB5" ||
  ver == "15.3(3)JBB50" ||
  ver == "15.3(3)JBB6" ||
  ver == "15.3(3)JBB6a" ||
  ver == "15.3(3)JBB8" ||
  ver == "15.3(3)JC" ||
  ver == "15.3(3)JC1" ||
  ver == "15.3(3)JC2" ||
  ver == "15.3(3)JC3" ||
  ver == "15.3(3)JC4" ||
  ver == "15.3(3)JD" ||
  ver == "15.3(3)JD2" ||
  ver == "15.3(3)JN3" ||
  ver == "15.3(3)JN4" ||
  ver == "15.3(3)JN7" ||
  ver == "15.3(3)JN8" ||
  ver == "15.3(3)JNB" ||
  ver == "15.3(3)JNB1" ||
  ver == "15.3(3)JNB2" ||
  ver == "15.3(3)JNB3" ||
  ver == "15.3(3)JNC" ||
  ver == "15.3(3)JNC1" ||
  ver == "15.3(3)JNP" ||
  ver == "15.3(3)JNP1" ||
  ver == "15.3(3)JNP2" ||
  ver == "15.3(3)JPB" ||
  ver == "15.3(3)M" ||
  ver == "15.3(3)M1" ||
  ver == "15.3(3)M2" ||
  ver == "15.3(3)M3" ||
  ver == "15.3(3)M4" ||
  ver == "15.3(3)M5" ||
  ver == "15.3(3)M6" ||
  ver == "15.3(3)M7" ||
  ver == "15.3(3)M8" ||
  ver == "15.3(3)M8a" ||
  ver == "15.3(3)S" ||
  ver == "15.3(3)S1" ||
  ver == "15.3(3)S1a" ||
  ver == "15.3(3)S2" ||
  ver == "15.3(3)S3" ||
  ver == "15.3(3)S4" ||
  ver == "15.3(3)S5" ||
  ver == "15.3(3)S6" ||
  ver == "15.3(3)S7" ||
  ver == "15.3(3)S8" ||
  ver == "15.3(3)S8a" ||
  ver == "15.4(1)CG" ||
  ver == "15.4(1)CG1" ||
  ver == "15.4(1)S" ||
  ver == "15.4(1)S1" ||
  ver == "15.4(1)S2" ||
  ver == "15.4(1)S3" ||
  ver == "15.4(1)S4" ||
  ver == "15.4(1)T" ||
  ver == "15.4(1)T1" ||
  ver == "15.4(1)T2" ||
  ver == "15.4(1)T3" ||
  ver == "15.4(1)T4" ||
  ver == "15.4(2)CG" ||
  ver == "15.4(2)S1" ||
  ver == "15.4(2)S2" ||
  ver == "15.4(2)S3" ||
  ver == "15.4(2)S4" ||
  ver == "15.4(2)T" ||
  ver == "15.4(2)T1" ||
  ver == "15.4(2)T2" ||
  ver == "15.4(2)T3" ||
  ver == "15.4(2)T4" ||
  ver == "15.4(3)M" ||
  ver == "15.4(3)M1" ||
  ver == "15.4(3)M2" ||
  ver == "15.4(3)M3" ||
  ver == "15.4(3)M4" ||
  ver == "15.4(3)M5" ||
  ver == "15.4(3)M6" ||
  ver == "15.4(3)M6a" ||
  ver == "15.4(3)S" ||
  ver == "15.4(3)S1" ||
  ver == "15.4(3)S2" ||
  ver == "15.4(3)S3" ||
  ver == "15.4(3)S4" ||
  ver == "15.4(3)S5" ||
  ver == "15.5(1)S" ||
  ver == "15.5(1)S1" ||
  ver == "15.5(1)S2" ||
  ver == "15.5(1)S3" ||
  ver == "15.5(1)S4" ||
  ver == "15.5(1)T" ||
  ver == "15.5(1)T1" ||
  ver == "15.5(1)T2" ||
  ver == "15.5(1)T3" ||
  ver == "15.5(1)T4" ||
  ver == "15.5(2)S" ||
  ver == "15.5(2)S1" ||
  ver == "15.5(2)S2" ||
  ver == "15.5(2)S3" ||
  ver == "15.5(2)S4" ||
  ver == "15.5(2)T" ||
  ver == "15.5(2)T1" ||
  ver == "15.5(2)T2" ||
  ver == "15.5(2)T3" ||
  ver == "15.5(2)T4" ||
  ver == "15.5(3)M" ||
  ver == "15.5(3)M0a" ||
  ver == "15.5(3)M1" ||
  ver == "15.5(3)M2" ||
  ver == "15.5(3)M3" ||
  ver == "15.5(3)M4" ||
  ver == "15.5(3)M4a" ||
  ver == "15.5(3)S" ||
  ver == "15.5(3)S0a" ||
  ver == "15.5(3)S1" ||
  ver == "15.5(3)S1a" ||
  ver == "15.5(3)S2" ||
  ver == "15.5(3)SN" ||
  ver == "15.6(1)S" ||
  ver == "15.6(1)S1" ||
  ver == "15.6(1)T" ||
  ver == "15.6(1)T0a" ||
  ver == "15.6(1)T1" ||
  ver == "15.6(1)T2" ||
  ver == "15.6(2)S" ||
  ver == "15.6(2)T" 
) flag++;

cmds = make_list();
# Check for the presence of an L2TPv3 pseudowire configuration or an
# L2TP virtual private dialup network (VPDN) configuration
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show run | include vpdn|pseudowire|xconnect","show run | include vpdn|pseudowire|xconnect");
  if (check_cisco_result(buf))
  {
    if ( ("vpdn enable" >< buf) || ("pseudowire-class" >< buf) || ("xconnect " >< buf) )
    {
      cmds = make_list(cmds, "show run | include vpdn|pseudowire|xconnect");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuy82078",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

