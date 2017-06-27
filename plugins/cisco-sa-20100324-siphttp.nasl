#TRUSTED 49e907d2ef14edd285da6161e2a812e3b098aeacc217e6beb8b9de661a8dce494c016744828cbc982287bb165ae17eb8eb5f2acbc220f7b55ecb9ed3338126b57248145e7e9cc37ef19841f667f4c05d5a4bbcbcf29fff88ff683486ea3440c345013b131765f683a1f6f133baa20eb832a005b1c4d888e9f8ced9c71c3998d5856af63701370849b7314cc1afdea365bb53c67101b60c929a47bcc56176042a63c4df6438b62cc4a637c945c35218dc01e5565d88c843773233b12c5da89a151b4ac23fbcb8029a37f0fbd6048c30f49858888c5e71efb387eddfd1addf10e0a9f96698ef0355d50b6b42db59dd961115f003febf8953d383d4e441bcdd9fd2d15eeae27929ddb9efb9b3f1bdd99ab4416b2907e0672d1e97a0d845bde86ad3902d51dc39d597e45998a55d75b4dce597adc57c3f278870848b1306fc7975255de7e978ef9078a8dbbcc99adfcb9b93ca5a817cd54bbe927284c6e1b8d4d91fde97cbb278bebdc0912523f869f37e6eab07228c98604e5f87d6f6de14f4be83275301e46bb593d10c5a0159823361bc92c28093e4174c86fb3902356c219500a598567b68f65e7889b6ca2fd0b4ee55759a6097f383c32a90965e2e50ac7739f87bfd4d7873e33381a16daaf4087add38a530025883c5ee0a4e6273b60e17e0be8ef15ba089f2f0ba764dcd948f0019306c4f89d0547850057c682beba23f2a
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100324-sip.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(49054);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2010-0579", "CVE-2010-0580", "CVE-2010-0581");
  script_osvdb_id(63183, 63184, 63185);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsz48680");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsz89904");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtb93416");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100324-sip");

  script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service Vulnerabilities (cisco-sa-20100324-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities exist in the Session Initiation Protocol
(SIP) implementation in Cisco IOS Software that could allow an
unauthenticated, remote attacker to cause a reload of an affected
device when SIP operation is enabled. Remote code execution may also
be possible. Cisco has released free software updates that address
these vulnerabilities. For devices that must run SIP there are no
workarounds; however, mitigations are available to limit exposure of
the vulnerabilities."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100324-sip
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7378b50c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100324-sip."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
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
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.3(11)T' ) flag++;
if ( version == '12.3(11)T1' ) flag++;
if ( version == '12.3(11)T10' ) flag++;
if ( version == '12.3(11)T11' ) flag++;
if ( version == '12.3(11)T12' ) flag++;
if ( version == '12.3(11)T2' ) flag++;
if ( version == '12.3(11)T2a' ) flag++;
if ( version == '12.3(11)T3' ) flag++;
if ( version == '12.3(11)T4' ) flag++;
if ( version == '12.3(11)T5' ) flag++;
if ( version == '12.3(11)T6' ) flag++;
if ( version == '12.3(11)T7' ) flag++;
if ( version == '12.3(11)T8' ) flag++;
if ( version == '12.3(11)T9' ) flag++;
if ( version == '12.3(11)XL' ) flag++;
if ( version == '12.3(11)XL1' ) flag++;
if ( version == '12.3(11)XL2' ) flag++;
if ( version == '12.3(11)XL3' ) flag++;
if ( version == '12.3(11)YF' ) flag++;
if ( version == '12.3(11)YF1' ) flag++;
if ( version == '12.3(11)YF2' ) flag++;
if ( version == '12.3(11)YF3' ) flag++;
if ( version == '12.3(11)YF4' ) flag++;
if ( version == '12.3(11)YK' ) flag++;
if ( version == '12.3(11)YK1' ) flag++;
if ( version == '12.3(11)YK2' ) flag++;
if ( version == '12.3(11)YL' ) flag++;
if ( version == '12.3(11)YL1' ) flag++;
if ( version == '12.3(11)YL2' ) flag++;
if ( version == '12.3(11)YN' ) flag++;
if ( version == '12.3(11)YR' ) flag++;
if ( version == '12.3(11)YR1' ) flag++;
if ( version == '12.3(11)YS2' ) flag++;
if ( version == '12.3(11)YW' ) flag++;
if ( version == '12.3(11)YW1' ) flag++;
if ( version == '12.3(11)YW2' ) flag++;
if ( version == '12.3(11)YZ' ) flag++;
if ( version == '12.3(11)YZ1' ) flag++;
if ( version == '12.3(11)YZ2' ) flag++;
if ( version == '12.3(11)ZB' ) flag++;
if ( version == '12.3(11)ZB1' ) flag++;
if ( version == '12.3(11)ZB2' ) flag++;
if ( version == '12.3(14)T' ) flag++;
if ( version == '12.3(14)T1' ) flag++;
if ( version == '12.3(14)T2' ) flag++;
if ( version == '12.3(14)T3' ) flag++;
if ( version == '12.3(14)T4' ) flag++;
if ( version == '12.3(14)T5' ) flag++;
if ( version == '12.3(14)T6' ) flag++;
if ( version == '12.3(14)T7' ) flag++;
if ( version == '12.3(14)YM1' ) flag++;
if ( version == '12.3(14)YM10' ) flag++;
if ( version == '12.3(14)YM11' ) flag++;
if ( version == '12.3(14)YM12' ) flag++;
if ( version == '12.3(14)YM13' ) flag++;
if ( version == '12.3(14)YM2' ) flag++;
if ( version == '12.3(14)YM3' ) flag++;
if ( version == '12.3(14)YM4' ) flag++;
if ( version == '12.3(14)YM5' ) flag++;
if ( version == '12.3(14)YM6' ) flag++;
if ( version == '12.3(14)YM7' ) flag++;
if ( version == '12.3(14)YM8' ) flag++;
if ( version == '12.3(14)YM9' ) flag++;
if ( version == '12.3(14)YQ' ) flag++;
if ( version == '12.3(14)YQ1' ) flag++;
if ( version == '12.3(14)YQ2' ) flag++;
if ( version == '12.3(14)YQ3' ) flag++;
if ( version == '12.3(14)YQ4' ) flag++;
if ( version == '12.3(14)YQ5' ) flag++;
if ( version == '12.3(14)YQ6' ) flag++;
if ( version == '12.3(14)YQ7' ) flag++;
if ( version == '12.3(14)YQ8' ) flag++;
if ( version == '12.3(14)YT' ) flag++;
if ( version == '12.3(14)YT1' ) flag++;
if ( version == '12.3(14)YU' ) flag++;
if ( version == '12.3(14)YU1' ) flag++;
if ( version == '12.3(14)YX' ) flag++;
if ( version == '12.3(14)YX1' ) flag++;
if ( version == '12.3(14)YX10' ) flag++;
if ( version == '12.3(14)YX11' ) flag++;
if ( version == '12.3(14)YX12' ) flag++;
if ( version == '12.3(14)YX13' ) flag++;
if ( version == '12.3(14)YX14' ) flag++;
if ( version == '12.3(14)YX15' ) flag++;
if ( version == '12.3(14)YX2' ) flag++;
if ( version == '12.3(14)YX3' ) flag++;
if ( version == '12.3(14)YX4' ) flag++;
if ( version == '12.3(14)YX7' ) flag++;
if ( version == '12.3(14)YX8' ) flag++;
if ( version == '12.3(14)YX9' ) flag++;
if ( version == '12.3(2)XF' ) flag++;
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
if ( version == '12.3(4)XG5' ) flag++;
if ( version == '12.3(4)XH' ) flag++;
if ( version == '12.3(4)XH1' ) flag++;
if ( version == '12.3(4)XK' ) flag++;
if ( version == '12.3(4)XK1' ) flag++;
if ( version == '12.3(4)XK2' ) flag++;
if ( version == '12.3(4)XK3' ) flag++;
if ( version == '12.3(4)XK4' ) flag++;
if ( version == '12.3(4)XQ' ) flag++;
if ( version == '12.3(4)XQ1' ) flag++;
if ( version == '12.3(7)T' ) flag++;
if ( version == '12.3(7)T1' ) flag++;
if ( version == '12.3(7)T10' ) flag++;
if ( version == '12.3(7)T11' ) flag++;
if ( version == '12.3(7)T12' ) flag++;
if ( version == '12.3(7)T2' ) flag++;
if ( version == '12.3(7)T3' ) flag++;
if ( version == '12.3(7)T4' ) flag++;
if ( version == '12.3(7)T5' ) flag++;
if ( version == '12.3(7)T6' ) flag++;
if ( version == '12.3(7)T7' ) flag++;
if ( version == '12.3(7)T8' ) flag++;
if ( version == '12.3(7)T9' ) flag++;
if ( version == '12.3(7)XI' ) flag++;
if ( version == '12.3(7)XI1' ) flag++;
if ( version == '12.3(7)XI10a' ) flag++;
if ( version == '12.3(7)XI2' ) flag++;
if ( version == '12.3(7)XI2b' ) flag++;
if ( version == '12.3(7)XI3' ) flag++;
if ( version == '12.3(7)XI4' ) flag++;
if ( version == '12.3(7)XI5' ) flag++;
if ( version == '12.3(7)XI6' ) flag++;
if ( version == '12.3(7)XI7' ) flag++;
if ( version == '12.3(7)XI7a' ) flag++;
if ( version == '12.3(7)XI7b' ) flag++;
if ( version == '12.3(7)XI8' ) flag++;
if ( version == '12.3(7)XI8bc' ) flag++;
if ( version == '12.3(7)XI8g' ) flag++;
if ( version == '12.3(7)XJ' ) flag++;
if ( version == '12.3(7)XJ1' ) flag++;
if ( version == '12.3(7)XJ2' ) flag++;
if ( version == '12.3(7)XL' ) flag++;
if ( version == '12.3(7)XM' ) flag++;
if ( version == '12.3(7)XR' ) flag++;
if ( version == '12.3(7)XR3' ) flag++;
if ( version == '12.3(7)XR4' ) flag++;
if ( version == '12.3(7)XR5' ) flag++;
if ( version == '12.3(7)XR6' ) flag++;
if ( version == '12.3(7)XR7' ) flag++;
if ( version == '12.3(7)YB' ) flag++;
if ( version == '12.3(7)YB1' ) flag++;
if ( version == '12.3(8)T' ) flag++;
if ( version == '12.3(8)T1' ) flag++;
if ( version == '12.3(8)T10' ) flag++;
if ( version == '12.3(8)T11' ) flag++;
if ( version == '12.3(8)T2' ) flag++;
if ( version == '12.3(8)T3' ) flag++;
if ( version == '12.3(8)T4' ) flag++;
if ( version == '12.3(8)T5' ) flag++;
if ( version == '12.3(8)T6' ) flag++;
if ( version == '12.3(8)T7' ) flag++;
if ( version == '12.3(8)T8' ) flag++;
if ( version == '12.3(8)T9' ) flag++;
if ( version == '12.3(8)XU2' ) flag++;
if ( version == '12.3(8)XU3' ) flag++;
if ( version == '12.3(8)XU4' ) flag++;
if ( version == '12.3(8)XU5' ) flag++;
if ( version == '12.3(8)XW' ) flag++;
if ( version == '12.3(8)XW1' ) flag++;
if ( version == '12.3(8)XW1a' ) flag++;
if ( version == '12.3(8)XW1b' ) flag++;
if ( version == '12.3(8)XW2' ) flag++;
if ( version == '12.3(8)XW3' ) flag++;
if ( version == '12.3(8)XX' ) flag++;
if ( version == '12.3(8)XX1' ) flag++;
if ( version == '12.3(8)XX2d' ) flag++;
if ( version == '12.3(8)XX2e' ) flag++;
if ( version == '12.3(8)XY' ) flag++;
if ( version == '12.3(8)XY1' ) flag++;
if ( version == '12.3(8)XY2' ) flag++;
if ( version == '12.3(8)XY3' ) flag++;
if ( version == '12.3(8)XY4' ) flag++;
if ( version == '12.3(8)XY5' ) flag++;
if ( version == '12.3(8)XY6' ) flag++;
if ( version == '12.3(8)XY7' ) flag++;
if ( version == '12.3(8)YC' ) flag++;
if ( version == '12.3(8)YC1' ) flag++;
if ( version == '12.3(8)YC2' ) flag++;
if ( version == '12.3(8)YC3' ) flag++;
if ( version == '12.3(8)YG' ) flag++;
if ( version == '12.3(8)YG2' ) flag++;
if ( version == '12.3(8)YG3' ) flag++;
if ( version == '12.3(8)YG4' ) flag++;
if ( version == '12.3(8)YG6' ) flag++;
if ( version == '12.3(8)ZA' ) flag++;
if ( version == '12.3(8)ZA1' ) flag++;
if ( version == '12.4(1)' ) flag++;
if ( version == '12.4(10)' ) flag++;
if ( version == '12.4(10a)' ) flag++;
if ( version == '12.4(10b)' ) flag++;
if ( version == '12.4(10c)' ) flag++;
if ( version == '12.4(12)' ) flag++;
if ( version == '12.4(12a)' ) flag++;
if ( version == '12.4(12b)' ) flag++;
if ( version == '12.4(12c)' ) flag++;
if ( version == '12.4(13)' ) flag++;
if ( version == '12.4(13a)' ) flag++;
if ( version == '12.4(13b)' ) flag++;
if ( version == '12.4(13c)' ) flag++;
if ( version == '12.4(13d)' ) flag++;
if ( version == '12.4(13e)' ) flag++;
if ( version == '12.4(13f)' ) flag++;
if ( version == '12.4(16)' ) flag++;
if ( version == '12.4(16a)' ) flag++;
if ( version == '12.4(16b)' ) flag++;
if ( version == '12.4(17)' ) flag++;
if ( version == '12.4(17a)' ) flag++;
if ( version == '12.4(17b)' ) flag++;
if ( version == '12.4(18)' ) flag++;
if ( version == '12.4(18a)' ) flag++;
if ( version == '12.4(18b)' ) flag++;
if ( version == '12.4(18c)' ) flag++;
if ( version == '12.4(18d)' ) flag++;
if ( version == '12.4(18e)' ) flag++;
if ( version == '12.4(19)' ) flag++;
if ( version == '12.4(19a)' ) flag++;
if ( version == '12.4(19b)' ) flag++;
if ( version == '12.4(1a)' ) flag++;
if ( version == '12.4(1b)' ) flag++;
if ( version == '12.4(1c)' ) flag++;
if ( version == '12.4(2)MR' ) flag++;
if ( version == '12.4(2)MR1' ) flag++;
if ( version == '12.4(2)T' ) flag++;
if ( version == '12.4(2)T1' ) flag++;
if ( version == '12.4(2)T2' ) flag++;
if ( version == '12.4(2)T3' ) flag++;
if ( version == '12.4(2)T4' ) flag++;
if ( version == '12.4(2)T5' ) flag++;
if ( version == '12.4(2)T6' ) flag++;
if ( version == '12.4(2)XA' ) flag++;
if ( version == '12.4(2)XA1' ) flag++;
if ( version == '12.4(2)XA2' ) flag++;
if ( version == '12.4(2)XB' ) flag++;
if ( version == '12.4(2)XB1' ) flag++;
if ( version == '12.4(2)XB10' ) flag++;
if ( version == '12.4(2)XB11' ) flag++;
if ( version == '12.4(2)XB2' ) flag++;
if ( version == '12.4(2)XB3' ) flag++;
if ( version == '12.4(2)XB4' ) flag++;
if ( version == '12.4(2)XB5' ) flag++;
if ( version == '12.4(2)XB6' ) flag++;
if ( version == '12.4(2)XB7' ) flag++;
if ( version == '12.4(2)XB8' ) flag++;
if ( version == '12.4(2)XB9' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(21)' ) flag++;
if ( version == '12.4(21a)' ) flag++;
if ( version == '12.4(21a)M1' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)MD' ) flag++;
if ( version == '12.4(22)MD1' ) flag++;
if ( version == '12.4(22)MDA' ) flag++;
if ( version == '12.4(22)MDA1' ) flag++;
if ( version == '12.4(22)MF' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)XR' ) flag++;
if ( version == '12.4(22)XR1' ) flag++;
if ( version == '12.4(22)XR2' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YD' ) flag++;
if ( version == '12.4(22)YD1' ) flag++;
if ( version == '12.4(22)YD2' ) flag++;
if ( version == '12.4(22)YE' ) flag++;
if ( version == '12.4(22)YE1' ) flag++;
if ( version == '12.4(23)' ) flag++;
if ( version == '12.4(23a)' ) flag++;
if ( version == '12.4(23b)' ) flag++;
if ( version == '12.4(23b)M1' ) flag++;
if ( version == '12.4(23c)' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(25)' ) flag++;
if ( version == '12.4(25a)' ) flag++;
if ( version == '12.4(25b)' ) flag++;
if ( version == '12.4(3)' ) flag++;
if ( version == '12.4(3a)' ) flag++;
if ( version == '12.4(3b)' ) flag++;
if ( version == '12.4(3c)' ) flag++;
if ( version == '12.4(3d)' ) flag++;
if ( version == '12.4(3e)' ) flag++;
if ( version == '12.4(3f)' ) flag++;
if ( version == '12.4(3g)' ) flag++;
if ( version == '12.4(3h)' ) flag++;
if ( version == '12.4(3i)' ) flag++;
if ( version == '12.4(3j)' ) flag++;
if ( version == '12.4(4)MR' ) flag++;
if ( version == '12.4(4)MR1' ) flag++;
if ( version == '12.4(4)T' ) flag++;
if ( version == '12.4(4)T1' ) flag++;
if ( version == '12.4(4)T2' ) flag++;
if ( version == '12.4(4)T3' ) flag++;
if ( version == '12.4(4)T4' ) flag++;
if ( version == '12.4(4)T5' ) flag++;
if ( version == '12.4(4)T6' ) flag++;
if ( version == '12.4(4)T7' ) flag++;
if ( version == '12.4(4)T8' ) flag++;
if ( version == '12.4(4)XD' ) flag++;
if ( version == '12.4(4)XD1' ) flag++;
if ( version == '12.4(4)XD10' ) flag++;
if ( version == '12.4(4)XD11' ) flag++;
if ( version == '12.4(4)XD12' ) flag++;
if ( version == '12.4(4)XD2' ) flag++;
if ( version == '12.4(4)XD3' ) flag++;
if ( version == '12.4(4)XD4' ) flag++;
if ( version == '12.4(4)XD5' ) flag++;
if ( version == '12.4(4)XD6' ) flag++;
if ( version == '12.4(4)XD7' ) flag++;
if ( version == '12.4(4)XD8' ) flag++;
if ( version == '12.4(4)XD9' ) flag++;
if ( version == '12.4(5)' ) flag++;
if ( version == '12.4(5a)' ) flag++;
if ( version == '12.4(5a)M0' ) flag++;
if ( version == '12.4(5b)' ) flag++;
if ( version == '12.4(5c)' ) flag++;
if ( version == '12.4(6)MR' ) flag++;
if ( version == '12.4(6)MR1' ) flag++;
if ( version == '12.4(6)T' ) flag++;
if ( version == '12.4(6)T1' ) flag++;
if ( version == '12.4(6)T10' ) flag++;
if ( version == '12.4(6)T11' ) flag++;
if ( version == '12.4(6)T12' ) flag++;
if ( version == '12.4(6)T2' ) flag++;
if ( version == '12.4(6)T3' ) flag++;
if ( version == '12.4(6)T4' ) flag++;
if ( version == '12.4(6)T5' ) flag++;
if ( version == '12.4(6)T5a' ) flag++;
if ( version == '12.4(6)T5b' ) flag++;
if ( version == '12.4(6)T6' ) flag++;
if ( version == '12.4(6)T7' ) flag++;
if ( version == '12.4(6)T8' ) flag++;
if ( version == '12.4(6)T9' ) flag++;
if ( version == '12.4(6)XP' ) flag++;
if ( version == '12.4(6)XT' ) flag++;
if ( version == '12.4(6)XT1' ) flag++;
if ( version == '12.4(6)XT2' ) flag++;
if ( version == '12.4(7)' ) flag++;
if ( version == '12.4(7a)' ) flag++;
if ( version == '12.4(7b)' ) flag++;
if ( version == '12.4(7c)' ) flag++;
if ( version == '12.4(7d)' ) flag++;
if ( version == '12.4(7e)' ) flag++;
if ( version == '12.4(7f)' ) flag++;
if ( version == '12.4(7g)' ) flag++;
if ( version == '12.4(7h)' ) flag++;
if ( version == '12.4(8)' ) flag++;
if ( version == '12.4(8a)' ) flag++;
if ( version == '12.4(8b)' ) flag++;
if ( version == '12.4(8c)' ) flag++;
if ( version == '12.4(8d)' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SIP", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
