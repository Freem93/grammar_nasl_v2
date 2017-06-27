#TRUSTED 30b6ff00b96c339058c84a795e6b424994a94568ed4e116e67cd94f3e5c6c69a71f26e42f86cb77053b695271b04da3daa9184246be8703ea860dccccafd31689727cffab2d8b286b4a57744ce616e467094e1ec7086f15b95c31276329c91474269e86bb1c8c67dd7222e5aeec198a05a8e19cace862a3cfe140c053160c073d39d9abd868a5a20351e6d3e5aafaa667230d7b252b11b3854683757dfbca841faf82009188ad71367b5ab70c218c6f94436ad78545f3526c6c1b18ad3b0a6a894460473b77da3ff20a190b6568a70f9e6e472aa8d1b2bc9dc312647123345de786c8e3dc2038b44e3689f849fe1feb1b3c25c33e5d23cd0e4f4d63ae088ed2385f7b7bf8a3a0173e3e5a34d543be31f611680784c09fd77f2651b730b64e4f2bce7976065b88d7a419e2a1c0ff4bb34d2cd3057bec384b4a5fee2bface33bd2d661bc320e8c9c6aad8bfa8d47ce9eac5b4baedaaa3cef67dc1539c4882e68daf573cbc1a2bab0f3b421839c18678db8cf9778545d5a9d930c65a1a0fc427688acb5f0d1ea08020c5f6a0eddc5c5a66ce3dd4ec12ca02db21274da146e23fb44cd5dd7d2e542ec928939dcc7fa232c051d74b5291ec6b5a8cf0c2b0020ed800935ba0eee4f0e7d82d26fe0ce29beb019766bcc2b60d95eb7a18eb69ef4234c6ec82a56343e9cf39e51e7fd63c6c5963aa61aa39160476c7ad844b038144123c2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73345);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2109", "CVE-2014-2111");
  script_bugtraq_id(66470);
  script_osvdb_id(104966, 104971);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj41494");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh33843");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue00996");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-nat");

  script_name(english:"Cisco IOS Software Multiple Network Address Translation (NAT) Denial of Service Vulnerabilities (cisco-sa-20140326-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by multiple denial of service
vulnerabilities in the Network Address Translation (NAT)
implementation :

  - An issue exists in the TCP Input module due to the
    improper handling of certain sequences of TCP packets.
    An unauthenticated, remote attacker could potentially
    exploit this issue by sending a specific sequence of
    IPv4 TCP packets resulting in a denial of service.
    (CVE-2014-2109)

  - An issue exists in the Application Layer Gateway (ALG)
    module due to the improper handling of malformed DNS
    packets during the NAT procedure. An unauthenticated,
    remote attacker could potentially exploit this issue by
    sending malformed IPv4 DNS packets resulting in a denial
    of service. (CVE-2014-2111)

Note that IPv6 packets cannot be used to exploit these issues.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-nat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bde264a3");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33347");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33349");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-nat.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
report = "";
fixed_ver = "";
cbi = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# CVE-2014-2109 / CVE-2014-2111
#15.2E
if (ver == "15.2(1)E")
{
  cbi = "CSCue00996, CSCuh33843, and CSCuj41494";
  fixed_ver = "15.2(1)E2";
}

#15.3S
else if (ver == "15.3(1)S1e" || ver == "15.3(2)S0a" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1" || ver == "15.3(2)S1b" || ver == "15.3(2)S1c" || ver == "15.3(2)S2" || ver == "15.3(3)S0b")
{
  cbi = "CSCue00996, CSCuh33843, and CSCuj41494";
  fixed_ver = "15.3(3)S2";
}


# CVE-2014-2109
#15.2JAY
if (ver == "15.2(4)JAY")
{
  cbi = "CSCuh33843 and CSCuj41494";
  fixed_ver = "Refer to the vendor for a fix.";
}


# CVE-2014-2111

if (!cbi) cbi = "CSCue00996";

#12.1
if (ver == "12.1(2)" || ver == "12.1(2a)" || ver == "12.1(2b)" || ver == "12.1(3)" || ver == "12.1(3b)" || ver == "12.1(4a)" || ver == "12.1(4b)" || ver == "12.1(4c)" || ver == "12.1(5)" || ver == "12.1(5a)" || ver == "12.1(5b)" || ver == "12.1(5c)" || ver == "12.1(5d)" || ver == "12.1(5e)" || ver == "12.1(6)" || ver == "12.1(6a)" || ver == "12.1(6b)" || ver == "12.1(7)" || ver == "12.1(7a)" || ver == "12.1(7b)" || ver == "12.1(7c)" || ver == "12.1(8)" || ver == "12.1(8a)" || ver == "12.1(8b)" || ver == "12.1(8c)" || ver == "12.1(9)" || ver == "12.1(9a)" || ver == "12.1(10)" || ver == "12.1(10a)" || ver == "12.1(11)" || ver == "12.1(11a)" || ver == "12.1(11b)" || ver == "12.1(12)" || ver == "12.1(12a)" || ver == "12.1(12b)" || ver == "12.1(12c)" || ver == "12.1(12d)" || ver == "12.1(13)" || ver == "12.1(13a)" || ver == "12.1(14)" || ver == "12.1(15)" || ver == "12.1(16)" || ver == "12.1(17)" || ver == "12.1(17a)" || ver == "12.1(18)" || ver == "12.1(19)" || ver == "12.1(20)" || ver == "12.1(20a)" || ver == "12.1(21)" || ver == "12.1(22)" || ver == "12.1(22a)" || ver == "12.1(22b)" || ver == "12.1(22c)" || ver == "12.1(24)" || ver == "12.1(25)" || ver == "12.1(26)" || ver == "12.1(27)" || ver == "12.1(27a)" || ver == "12.1(27b)")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1AZ
else if (ver == "12.1(14)AZ")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1E
else if (ver == "12.1(2)E" || ver == "12.1(2)E1" || ver == "12.1(2)E2" || ver == "12.1(3a)E" || ver == "12.1(3a)E1" || ver == "12.1(3a)E3" || ver == "12.1(3a)E4" || ver == "12.1(3a)E5" || ver == "12.1(3a)E6" || ver == "12.1(3a)E7" || ver == "12.1(3a)E8" || ver == "12.1(4)E" || ver == "12.1(4)E1" || ver == "12.1(4)E3" || ver == "12.1(5a)E" || ver == "12.1(5a)E1" || ver == "12.1(5a)E2" || ver == "12.1(5a)E3" || ver == "12.1(5a)E4" || ver == "12.1(5b)E7" || ver == "12.1(5c)E10" || ver == "12.1(5c)E12" || ver == "12.1(5c)E8" || ver == "12.1(5c)E9" || ver == "12.1(6)E" || ver == "12.1(6)E1" || ver == "12.1(6)E10" || ver == "12.1(6)E11" || ver == "12.1(6)E12" || ver == "12.1(6)E13" || ver == "12.1(6)E2" || ver == "12.1(6)E3" || ver == "12.1(6)E4" || ver == "12.1(6)E5" || ver == "12.1(6)E6" || ver == "12.1(6)E8" || ver == "12.1(6)E9" || ver == "12.1(7)E" || ver == "12.1(7)E0a" || ver == "12.1(7a)E1" || ver == "12.1(7a)E1a" || ver == "12.1(7a)E2" || ver == "12.1(7a)E3" || ver == "12.1(7a)E4" || ver == "12.1(7a)E5" || ver == "12.1(7a)E6" || ver == "12.1(8a)E" || ver == "12.1(8a)E1" || ver == "12.1(8a)E2" || ver == "12.1(8a)E3" || ver == "12.1(8a)E4" || ver == "12.1(8a)E5" || ver == "12.1(8b)E10" || ver == "12.1(8b)E11" || ver == "12.1(8b)E12" || ver == "12.1(8b)E13" || ver == "12.1(8b)E14" || ver == "12.1(8b)E15" || ver == "12.1(8b)E16" || ver == "12.1(8b)E18" || ver == "12.1(8b)E19" || ver == "12.1(8b)E20" || ver == "12.1(8b)E6" || ver == "12.1(8b)E7" || ver == "12.1(8b)E8" || ver == "12.1(8b)E9" || ver == "12.1(9)E" || ver == "12.1(9)E1" || ver == "12.1(9)E2" || ver == "12.1(9)E3" || ver == "12.1(10)E" || ver == "12.1(10)E1" || ver == "12.1(10)E2" || ver == "12.1(10)E3" || ver == "12.1(10)E4" || ver == "12.1(10)E5" || ver == "12.1(10)E6" || ver == "12.1(10)E6a" || ver == "12.1(10)E7" || ver == "12.1(10)E8" || ver == "12.1(11b)E" || ver == "12.1(11b)E0a" || ver == "12.1(11b)E1" || ver == "12.1(11b)E10" || ver == "12.1(11b)E11" || ver == "12.1(11b)E12" || ver == "12.1(11b)E14" || ver == "12.1(11b)E2" || ver == "12.1(11b)E3" || ver == "12.1(11b)E4" || ver == "12.1(11b)E6" || ver == "12.1(11b)E7" || ver == "12.1(11b)E8" || ver == "12.1(11b)E9" || ver == "12.1(12c)E" || ver == "12.1(12c)E1" || ver == "12.1(12c)E2" || ver == "12.1(12c)E4" || ver == "12.1(12c)E5" || ver == "12.1(12c)E6" || ver == "12.1(12c)E7" || ver == "12.1(13)E" || ver == "12.1(13)E1" || ver == "12.1(13)E10" || ver == "12.1(13)E11" || ver == "12.1(13)E12" || ver == "12.1(13)E13" || ver == "12.1(13)E14" || ver == "12.1(13)E15" || ver == "12.1(13)E16" || ver == "12.1(13)E17" || ver == "12.1(13)E2" || ver == "12.1(13)E3" || ver == "12.1(13)E4" || ver == "12.1(13)E5" || ver == "12.1(13)E6" || ver == "12.1(13)E7" || ver == "12.1(13)E8" || ver == "12.1(13)E9" || ver == "12.1(14)E" || ver == "12.1(14)E1" || ver == "12.1(14)E10" || ver == "12.1(14)E2" || ver == "12.1(14)E3" || ver == "12.1(14)E4" || ver == "12.1(14)E5" || ver == "12.1(14)E6" || ver == "12.1(14)E7" || ver == "12.1(14)E8" || ver == "12.1(19)E" || ver == "12.1(19)E1" || ver == "12.1(19)E1a" || ver == "12.1(19)E2" || ver == "12.1(19)E3" || ver == "12.1(19)E4" || ver == "12.1(19)E6" || ver == "12.1(19)E7" || ver == "12.1(20)E" || ver == "12.1(20)E1" || ver == "12.1(20)E2" || ver == "12.1(20)E3" || ver == "12.1(20)E4" || ver == "12.1(20)E5" || ver == "12.1(20)E6" || ver == "12.1(22)E" || ver == "12.1(22)E1" || ver == "12.1(22)E2" || ver == "12.1(22)E3" || ver == "12.1(22)E4" || ver == "12.1(22)E5" || ver == "12.1(22)E6" || ver == "12.1(23)E" || ver == "12.1(23)E1" || ver == "12.1(23)E2" || ver == "12.1(23)E3" || ver == "12.1(23)E4" || ver == "12.1(26)E" || ver == "12.1(26)E1" || ver == "12.1(26)E2" || ver == "12.1(26)E3" || ver == "12.1(26)E4" || ver == "12.1(26)E5" || ver == "12.1(26)E6" || ver == "12.1(26)E7" || ver == "12.1(26)E8" || ver == "12.1(26)E9" || ver == "12.1(27b)E" || ver == "12.1(27b)E1" || ver == "12.1(27b)E2" || ver == "12.1(27b)E3" || ver == "12.1(27b)E4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1EA
else if (ver == "12.1(6)EA1" || ver == "12.1(8)EA1c" || ver == "12.1(9)EA1" || ver == "12.1(11)EA1" || ver == "12.1(11)EA1a" || ver == "12.1(12c)EA1" || ver == "12.1(12c)EA1a" || ver == "12.1(13)EA1" || ver == "12.1(13)EA1a" || ver == "12.1(13)EA1b" || ver == "12.1(13)EA1c" || ver == "12.1(14)EA1" || ver == "12.1(14)EA1a" || ver == "12.1(14)EA1b" || ver == "12.1(19)EA1" || ver == "12.1(19)EA1a" || ver == "12.1(19)EA1b" || ver == "12.1(19)EA1c" || ver == "12.1(19)EA1d" || ver == "12.1(20)EA1" || ver == "12.1(20)EA1a" || ver == "12.1(20)EA2" || ver == "12.1(22)EA1" || ver == "12.1(22)EA1a" || ver == "12.1(22)EA1b" || ver == "12.1(22)EA10" || ver == "12.1(22)EA10a" || ver == "12.1(22)EA10b" || ver == "12.1(22)EA11" || ver == "12.1(22)EA12" || ver == "12.1(22)EA13" || ver == "12.1(22)EA14" || ver == "12.1(22)EA2" || ver == "12.1(22)EA3" || ver == "12.1(22)EA4" || ver == "12.1(22)EA4a" || ver == "12.1(22)EA5" || ver == "12.1(22)EA5a" || ver == "12.1(22)EA6" || ver == "12.1(22)EA6a" || ver == "12.1(22)EA7" || ver == "12.1(22)EA8" || ver == "12.1(22)EA8a" || ver == "12.1(22)EA9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1EC
else if (ver == "12.1(2)EC" || ver == "12.1(2)EC1" || ver == "12.1(3a)EC" || ver == "12.1(3a)EC1" || ver == "12.1(4)EC" || ver == "12.1(5)EC" || ver == "12.1(5)EC1" || ver == "12.1(6)EC" || ver == "12.1(6)EC1" || ver == "12.1(7)EC" || ver == "12.1(8)EC" || ver == "12.1(8)EC1" || ver == "12.1(9)EC1" || ver == "12.1(10)EC" || ver == "12.1(10)EC1" || ver == "12.1(11b)EC" || ver == "12.1(11b)EC1" || ver == "12.1(12c)EC" || ver == "12.1(12c)EC1" || ver == "12.1(13)EC" || ver == "12.1(13)EC1" || ver == "12.1(13)EC2" || ver == "12.1(13)EC3" || ver == "12.1(13)EC4" || ver == "12.1(19)EC" || ver == "12.1(19)EC1" || ver == "12.1(20)EC" || ver == "12.1(20)EC1" || ver == "12.1(20)EC2" || ver == "12.1(20)EC3" || ver == "12.1(22)EC" || ver == "12.1(22)EC1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1EX
else if (ver == "12.1(5c)EX3" || ver == "12.1(8a)EX" || ver == "12.1(8a)EX1" || ver == "12.1(8b)EX2" || ver == "12.1(8b)EX3" || ver == "12.1(8b)EX5" || ver == "12.1(9)EX" || ver == "12.1(9)EX1" || ver == "12.1(9)EX2" || ver == "12.1(9)EX3" || ver == "12.1(10)EX" || ver == "12.1(10)EX1" || ver == "12.1(10)EX2" || ver == "12.1(11b)EX" || ver == "12.1(11b)EX1" || ver == "12.1(12c)EX" || ver == "12.1(12c)EX1" || ver == "12.1(13)EX" || ver == "12.1(13)EX1" || ver == "12.1(13)EX2" || ver == "12.1(13)EX3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1GB
else if (ver == "12.1(2)GB")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1T
else if (ver == "12.1(2)T" || ver == "12.1(2a)T1" || ver == "12.1(2a)T2" || ver == "12.1(3)T" || ver == "12.1(3a)T1" || ver == "12.1(3a)T2" || ver == "12.1(3a)T3" || ver == "12.1(3a)T4" || ver == "12.1(3a)T5" || ver == "12.1(3a)T6" || ver == "12.1(3a)T7" || ver == "12.1(3a)T8" || ver == "12.1(5)T" || ver == "12.1(5)T1" || ver == "12.1(5)T10" || ver == "12.1(5)T11" || ver == "12.1(5)T12" || ver == "12.1(5)T13" || ver == "12.1(5)T14" || ver == "12.1(5)T15" || ver == "12.1(5)T17" || ver == "12.1(5)T18" || ver == "12.1(5)T19" || ver == "12.1(5)T2" || ver == "12.1(5)T20" || ver == "12.1(5)T3" || ver == "12.1(5)T4" || ver == "12.1(5)T5" || ver == "12.1(5)T6" || ver == "12.1(5)T7" || ver == "12.1(5)T8" || ver == "12.1(5)T8a" || ver == "12.1(5)T8b" || ver == "12.1(5)T8c" || ver == "12.1(5)T9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1XI
else if (ver == "12.1(3)XI" || ver == "12.1(3a)XI1" || ver == "12.1(3a)XI2" || ver == "12.1(3a)XI3" || ver == "12.1(3a)XI4" || ver == "12.1(3a)XI5" || ver == "12.1(3a)XI6" || ver == "12.1(3a)XI7" || ver == "12.1(3a)XI8" || ver == "12.1(3a)XI9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1XM
else if (ver == "12.1(5)XM" || ver == "12.1(5)XM1" || ver == "12.1(5)XM2" || ver == "12.1(5)XM3" || ver == "12.1(5)XM4" || ver == "12.1(5)XM5" || ver == "12.1(5)XM6" || ver == "12.1(5)XM7" || ver == "12.1(5)XM8")
  fixed_ver = "Refer to the vendor for a fix.";
#12.1YB
else if (ver == "12.1(5)YB" || ver == "12.1(5)YB1" || ver == "12.1(5)YB4" || ver == "12.1(5)YB5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2
else if (ver == "12.2(1)" || ver == "12.2(1a)" || ver == "12.2(1b)" || ver == "12.2(1c)" || ver == "12.2(1d)" || ver == "12.2(3)" || ver == "12.2(3a)" || ver == "12.2(3b)" || ver == "12.2(3c)" || ver == "12.2(3d)" || ver == "12.2(3e)" || ver == "12.2(3f)" || ver == "12.2(3g)" || ver == "12.2(5)" || ver == "12.2(5a)" || ver == "12.2(5b)" || ver == "12.2(5c)" || ver == "12.2(5d)" || ver == "12.2(6)" || ver == "12.2(6a)" || ver == "12.2(6b)" || ver == "12.2(6c)" || ver == "12.2(6d)" || ver == "12.2(6e)" || ver == "12.2(6f)" || ver == "12.2(6g)" || ver == "12.2(6h)" || ver == "12.2(6i)" || ver == "12.2(6j)" || ver == "12.2(7)" || ver == "12.2(7a)" || ver == "12.2(7b)" || ver == "12.2(7c)" || ver == "12.2(7d)" || ver == "12.2(7e)" || ver == "12.2(7f)" || ver == "12.2(7g)" || ver == "12.2(10)" || ver == "12.2(10a)" || ver == "12.2(10b)" || ver == "12.2(10c)" || ver == "12.2(10d)" || ver == "12.2(10g)" || ver == "12.2(12)" || ver == "12.2(12a)" || ver == "12.2(12b)" || ver == "12.2(12c)" || ver == "12.2(12d)" || ver == "12.2(12e)" || ver == "12.2(12f)" || ver == "12.2(12g)" || ver == "12.2(12h)" || ver == "12.2(12i)" || ver == "12.2(12j)" || ver == "12.2(12k)" || ver == "12.2(12l)" || ver == "12.2(12m)" || ver == "12.2(13)" || ver == "12.2(13a)" || ver == "12.2(13b)" || ver == "12.2(13c)" || ver == "12.2(13e)" || ver == "12.2(16)" || ver == "12.2(16a)" || ver == "12.2(16b)" || ver == "12.2(16c)" || ver == "12.2(16f)" || ver == "12.2(17)" || ver == "12.2(17a)" || ver == "12.2(17b)" || ver == "12.2(17d)" || ver == "12.2(17e)" || ver == "12.2(17f)" || ver == "12.2(19)" || ver == "12.2(19a)" || ver == "12.2(19b)" || ver == "12.2(19c)" || ver == "12.2(21)" || ver == "12.2(21a)" || ver == "12.2(21b)" || ver == "12.2(23)" || ver == "12.2(23a)" || ver == "12.2(23b)" || ver == "12.2(23c)" || ver == "12.2(23d)" || ver == "12.2(23e)" || ver == "12.2(23f)" || ver == "12.2(24)" || ver == "12.2(24a)" || ver == "12.2(24b)" || ver == "12.2(26)" || ver == "12.2(26a)" || ver == "12.2(26b)" || ver == "12.2(26c)" || ver == "12.2(27)" || ver == "12.2(27a)" || ver == "12.2(27b)" || ver == "12.2(27c)" || ver == "12.2(28)" || ver == "12.2(28a)" || ver == "12.2(28b)" || ver == "12.2(28c)" || ver == "12.2(28d)" || ver == "12.2(29)" || ver == "12.2(29a)" || ver == "12.2(29b)" || ver == "12.2(31)" || ver == "12.2(32)" || ver == "12.2(34)" || ver == "12.2(34a)" || ver == "12.2(37)" || ver == "12.2(40)" || ver == "12.2(40a)" || ver == "12.2(46)" || ver == "12.2(46a)")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2B
else if (ver == "12.2(2)B" || ver == "12.2(2)B1" || ver == "12.2(2)B2" || ver == "12.2(2)B3" || ver == "12.2(2)B4" || ver == "12.2(2)B5" || ver == "12.2(2)B6" || ver == "12.2(2)B7" || ver == "12.2(4)B" || ver == "12.2(4)B1" || ver == "12.2(4)B2" || ver == "12.2(4)B3" || ver == "12.2(4)B4" || ver == "12.2(4)B5" || ver == "12.2(4)B6" || ver == "12.2(4)B7" || ver == "12.2(4)B7a" || ver == "12.2(4)B8" || ver == "12.2(8)B" || ver == "12.2(8)B1" || ver == "12.2(8)B2" || ver == "12.2(15)B" || ver == "12.2(15)B1" || ver == "12.2(16)B" || ver == "12.2(16)B1" || ver == "12.2(16)B2" || ver == "12.2(16)B3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2BC
else if (ver == "12.2(4)BC1" || ver == "12.2(4)BC1a" || ver == "12.2(4)BC1b" || ver == "12.2(8)BC1" || ver == "12.2(8)BC2" || ver == "12.2(8)BC2a" || ver == "12.2(11)BC1" || ver == "12.2(11)BC1a" || ver == "12.2(11)BC1b" || ver == "12.2(11)BC2" || ver == "12.2(11)BC3" || ver == "12.2(11)BC3a" || ver == "12.2(11)BC3b" || ver == "12.2(11)BC3c" || ver == "12.2(11)BC3d" || ver == "12.2(15)BC1" || ver == "12.2(15)BC1a" || ver == "12.2(15)BC1b" || ver == "12.2(15)BC1c" || ver == "12.2(15)BC1d" || ver == "12.2(15)BC1f" || ver == "12.2(15)BC1g" || ver == "12.2(15)BC2" || ver == "12.2(15)BC2a" || ver == "12.2(15)BC2b" || ver == "12.2(15)BC2c" || ver == "12.2(15)BC2e" || ver == "12.2(15)BC2f" || ver == "12.2(15)BC2g" || ver == "12.2(15)BC2h" || ver == "12.2(15)BC2i")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2BW
else if (ver == "12.2(4)BW" || ver == "12.2(4)BW1" || ver == "12.2(4)BW1a" || ver == "12.2(4)BW2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2BX
else if (ver == "12.2(2)BX" || ver == "12.2(2)BX1" || ver == "12.2(2)BX2" || ver == "12.2(4)BX" || ver == "12.2(4)BX1" || ver == "12.2(4)BX1a" || ver == "12.2(4)BX1b" || ver == "12.2(4)BX1c" || ver == "12.2(4)BX1d" || ver == "12.2(4)BX2" || ver == "12.2(16)BX" || ver == "12.2(16)BX1" || ver == "12.2(16)BX2" || ver == "12.2(16)BX3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2BY
else if (ver == "12.2(4)BY" || ver == "12.2(4)BY1" || ver == "12.2(8)BY" || ver == "12.2(8)BY1" || ver == "12.2(8)BY2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2CX
else if (ver == "12.2(11)CX" || ver == "12.2(11)CX1" || ver == "12.2(15)CX" || ver == "12.2(15)CX1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2CZ
else if (ver == "12.2(15)CZ" || ver == "12.2(15)CZ1" || ver == "12.2(15)CZ2" || ver == "12.2(15)CZ3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2DD
else if (ver == "12.2(2)DD" || ver == "12.2(2)DD1" || ver == "12.2(2)DD2" || ver == "12.2(2)DD3" || ver == "12.2(2)DD4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2DX
else if (ver == "12.2(1)DX" || ver == "12.2(1)DX1" || ver == "12.2(2)DX" || ver == "12.2(2)DX1" || ver == "12.2(2)DX2" || ver == "12.2(2)DX3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2EU
else if (ver == "12.2(20)EU" || ver == "12.2(20)EU1" || ver == "12.2(20)EU2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2EW
else if (ver == "12.2(25)EW")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2EWA
else if (ver == "12.2(20)EWA" || ver == "12.2(20)EWA1" || ver == "12.2(20)EWA2" || ver == "12.2(20)EWA3" || ver == "12.2(20)EWA4" || ver == "12.2(25)EWA" || ver == "12.2(25)EWA1" || ver == "12.2(25)EWA10" || ver == "12.2(25)EWA11" || ver == "12.2(25)EWA12" || ver == "12.2(25)EWA13" || ver == "12.2(25)EWA14" || ver == "12.2(25)EWA2" || ver == "12.2(25)EWA3" || ver == "12.2(25)EWA4" || ver == "12.2(25)EWA5" || ver == "12.2(25)EWA6" || ver == "12.2(25)EWA7" || ver == "12.2(25)EWA8" || ver == "12.2(25)EWA9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2EX
else if (ver == "12.2(20)EX" || ver == "12.2(40)EX" || ver == "12.2(40)EX1" || ver == "12.2(40)EX2" || ver == "12.2(40)EX3" || ver == "12.2(46)EX" || ver == "12.2(52)EX" || ver == "12.2(52)EX1" || ver == "12.2(55)EX" || ver == "12.2(55)EX1" || ver == "12.2(55)EX2" || ver == "12.2(55)EX3" || ver == "12.2(58)EX")
  fixed_ver = "15.0(2)SE6";
#12.2EY
else if (ver == "12.2(25)EY" || ver == "12.2(25)EY1" || ver == "12.2(25)EY2" || ver == "12.2(25)EY3" || ver == "12.2(25)EY4" || ver == "12.2(37)EY" || ver == "12.2(46)EY" || ver == "12.2(52)EY" || ver == "12.2(52)EY1" || ver == "12.2(52)EY1b" || ver == "12.2(52)EY1c" || ver == "12.2(52)EY2" || ver == "12.2(52)EY2a" || ver == "12.2(52)EY3" || ver == "12.2(52)EY3a" || ver == "12.2(52)EY4" || ver == "12.2(53)EY" || ver == "12.2(55)EY")
  fixed_ver = "15.2(4)S5";
#12.2EYA
else if (ver == "12.2(52)EY1A")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2EZ
else if (ver == "12.2(25)EZ" || ver == "12.2(25)EZ1" || ver == "12.2(53)EZ" || ver == "12.2(55)EZ" || ver == "12.2(58)EZ")
  fixed_ver = "15.0(2)SE6";
#12.2FX
else if (ver == "12.2(25)FX")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2FY
else if (ver == "12.2(25)FY")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2FZ
else if (ver == "12.2(25)FZ")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IRA
else if (ver == "12.2(33)IRA")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IRB
else if (ver == "12.2(33)IRB")
  fixed_ver = "12.2(33)SRE10";
#12.2IRC
else if (ver == "12.2(33)IRC")
  fixed_ver = "12.2(33)SRE10";
#12.2IRD
else if (ver == "12.2(33)IRD")
  fixed_ver = "12.2(33)SRE10";
#12.2IRE
else if (ver == "12.2(33)IRE" || ver == "12.2(33)IRE1" || ver == "12.2(33)IRE2")
  fixed_ver = "12.2(33)SRE10";
#12.2IRF
else if (ver == "12.2(33)IRF")
  fixed_ver = "12.2(33)SRE10";
#12.2IRG
else if (ver == "12.2(33)IRG" || ver == "12.2(33)IRG1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IRH
else if (ver == "12.2(33)IRH" || ver == "12.2(33)IRH1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IRI
else if (ver == "12.2(33)IRI")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXA
else if (ver == "12.2(18)IXA")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXB
else if (ver == "12.2(18)IXB" || ver == "12.2(18)IXB1" || ver == "12.2(18)IXB2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXC
else if (ver == "12.2(18)IXC")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXD
else if (ver == "12.2(18)IXD" || ver == "12.2(18)IXD1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXE
else if (ver == "12.2(18)IXE")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXF
else if (ver == "12.2(18)IXF" || ver == "12.2(18)IXF1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXG
else if (ver == "12.2(18)IXG")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2IXH
else if (ver == "12.2(18)IXH" || ver == "12.2(18)IXH1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2M
else if (ver == "12.2(1)M0" || ver == "12.2(6c)M1" || ver == "12.2(12b)M1" || ver == "12.2(12h)M1" || ver == "12.2(13b)M1" || ver == "12.2(13b)M2" || ver == "12.2(23c)M0")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2MB
else if (ver == "12.2(1)MB1" || ver == "12.2(4)MB1" || ver == "12.2(4)MB10" || ver == "12.2(4)MB11" || ver == "12.2(4)MB12" || ver == "12.2(4)MB13" || ver == "12.2(4)MB13a" || ver == "12.2(4)MB13b" || ver == "12.2(4)MB13c" || ver == "12.2(4)MB2" || ver == "12.2(4)MB3" || ver == "12.2(4)MB4" || ver == "12.2(4)MB5" || ver == "12.2(4)MB6" || ver == "12.2(4)MB7" || ver == "12.2(4)MB8" || ver == "12.2(4)MB9" || ver == "12.2(4)MB9a")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2MC
else if (ver == "12.2(8)MC1" || ver == "12.2(8)MC2" || ver == "12.2(8)MC2a" || ver == "12.2(8)MC2b" || ver == "12.2(8)MC2c" || ver == "12.2(8)MC2d" || ver == "12.2(15)MC1" || ver == "12.2(15)MC1a" || ver == "12.2(15)MC1b" || ver == "12.2(15)MC1c" || ver == "12.2(15)MC2" || ver == "12.2(15)MC2a" || ver == "12.2(15)MC2b" || ver == "12.2(15)MC2c" || ver == "12.2(15)MC2e" || ver == "12.2(15)MC2f" || ver == "12.2(15)MC2g" || ver == "12.2(15)MC2h" || ver == "12.2(15)MC2i" || ver == "12.2(15)MC2j" || ver == "12.2(15)MC2k" || ver == "12.2(15)MC2l" || ver == "12.2(15)MC2m")
  fixed_ver = "15.1(4)M8";
#12.2MRA
else if (ver == "12.2(33)MRA")
  fixed_ver = "12.2(33)SRE10";
#12.2MRB
else if (ver == "12.2(33)MRB" || ver == "12.2(33)MRB1" || ver == "12.2(33)MRB2" || ver == "12.2(33)MRB3" || ver == "12.2(33)MRB4" || ver == "12.2(33)MRB5" || ver == "12.2(33)MRB6")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2MX
else if (ver == "12.2(4)MX" || ver == "12.2(4)MX1" || ver == "12.2(4)MX2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2S
else if (ver == "12.2(9)S" || ver == "12.2(11)S" || ver == "12.2(11)S1" || ver == "12.2(11)S2" || ver == "12.2(11)S3" || ver == "12.2(14)S" || ver == "12.2(14)S1" || ver == "12.2(14)S10" || ver == "12.2(14)S11" || ver == "12.2(14)S11a" || ver == "12.2(14)S11b" || ver == "12.2(14)S12" || ver == "12.2(14)S13" || ver == "12.2(14)S13a" || ver == "12.2(14)S13b" || ver == "12.2(14)S14" || ver == "12.2(14)S15" || ver == "12.2(14)S16" || ver == "12.2(14)S17" || ver == "12.2(14)S18" || ver == "12.2(14)S19" || ver == "12.2(14)S2" || ver == "12.2(14)S3" || ver == "12.2(14)S4" || ver == "12.2(14)S5" || ver == "12.2(14)S6" || ver == "12.2(14)S7" || ver == "12.2(14)S8" || ver == "12.2(14)S9" || ver == "12.2(14)S9a" || ver == "12.2(14)S9b" || ver == "12.2(14)S9c" || ver == "12.2(18)S" || ver == "12.2(18)S1" || ver == "12.2(18)S10" || ver == "12.2(18)S11" || ver == "12.2(18)S12" || ver == "12.2(18)S13" || ver == "12.2(18)S2" || ver == "12.2(18)S3" || ver == "12.2(18)S4" || ver == "12.2(18)S5" || ver == "12.2(18)S6" || ver == "12.2(18)S7" || ver == "12.2(18)S8" || ver == "12.2(18)S9" || ver == "12.2(20)S" || ver == "12.2(20)S1" || ver == "12.2(20)S10" || ver == "12.2(20)S11" || ver == "12.2(20)S12" || ver == "12.2(20)S13" || ver == "12.2(20)S14" || ver == "12.2(20)S2" || ver == "12.2(20)S2a" || ver == "12.2(20)S3" || ver == "12.2(20)S4" || ver == "12.2(20)S4a" || ver == "12.2(20)S5" || ver == "12.2(20)S6" || ver == "12.2(20)S6a" || ver == "12.2(20)S7" || ver == "12.2(20)S8" || ver == "12.2(20)S9" || ver == "12.2(20)S9a" || ver == "12.2(20)S9b" || ver == "12.2(22)S" || ver == "12.2(22)S1" || ver == "12.2(22)S2" || ver == "12.2(25)S" || ver == "12.2(25)S1" || ver == "12.2(25)S10" || ver == "12.2(25)S11" || ver == "12.2(25)S12" || ver == "12.2(25)S13" || ver == "12.2(25)S14" || ver == "12.2(25)S15" || ver == "12.2(25)S2" || ver == "12.2(25)S3" || ver == "12.2(25)S4" || ver == "12.2(25)S5" || ver == "12.2(25)S6" || ver == "12.2(25)S7" || ver == "12.2(25)S8" || ver == "12.2(25)S9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SB
else if (ver == "12.2(28)SB" || ver == "12.2(28)SB1" || ver == "12.2(28)SB10" || ver == "12.2(28)SB11" || ver == "12.2(28)SB12" || ver == "12.2(28)SB13" || ver == "12.2(28)SB2" || ver == "12.2(28)SB3" || ver == "12.2(28)SB4" || ver == "12.2(28)SB5" || ver == "12.2(28)SB6" || ver == "12.2(28)SB7" || ver == "12.2(28)SB8" || ver == "12.2(28)SB9" || ver == "12.2(31)SB" || ver == "12.2(31)SB1" || ver == "12.2(31)SB1f" || ver == "12.2(31)SB10" || ver == "12.2(31)SB10a" || ver == "12.2(31)SB10c" || ver == "12.2(31)SB10d" || ver == "12.2(31)SB10e" || ver == "12.2(31)SB11" || ver == "12.2(31)SB11a" || ver == "12.2(31)SB12" || ver == "12.2(31)SB12a" || ver == "12.2(31)SB13" || ver == "12.2(31)SB14" || ver == "12.2(31)SB15" || ver == "12.2(31)SB16" || ver == "12.2(31)SB17" || ver == "12.2(31)SB18" || ver == "12.2(31)SB19" || ver == "12.2(31)SB2" || ver == "12.2(31)SB20" || ver == "12.2(31)SB21" || ver == "12.2(31)SB3" || ver == "12.2(31)SB3x" || ver == "12.2(31)SB4" || ver == "12.2(31)SB4a" || ver == "12.2(31)SB5" || ver == "12.2(31)SB5a" || ver == "12.2(31)SB6" || ver == "12.2(31)SB7" || ver == "12.2(31)SB8" || ver == "12.2(31)SB8a" || ver == "12.2(31)SB9" || ver == "12.2(31)SB9b" || ver == "12.2(33)SB" || ver == "12.2(33)SB1" || ver == "12.2(33)SB10" || ver == "12.2(33)SB11" || ver == "12.2(33)SB12" || ver == "12.2(33)SB13" || ver == "12.2(33)SB14" || ver == "12.2(33)SB2" || ver == "12.2(33)SB3" || ver == "12.2(33)SB4" || ver == "12.2(33)SB5" || ver == "12.2(33)SB6" || ver == "12.2(33)SB7" || ver == "12.2(33)SB8" || ver == "12.2(33)SB8c" || ver == "12.2(33)SB8e" || ver == "12.2(33)SB9")
    fixed_ver = "12.2(33)SRE10";
#12.2SBA
else if (ver == "12.2(27)SBA" || ver == "12.2(27)SBA4" || ver == "12.2(27)SBA5" || ver == "12.2(27)SBA6")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SBB
else if (ver == "12.2(27)SBB" || ver == "12.2(27)SBB4d" || ver == "12.2(27)SBB6a" || ver == "12.2(27)SBB8")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SBC
else if (ver == "12.2(27)SBC" || ver == "12.2(27)SBC1" || ver == "12.2(27)SBC2" || ver == "12.2(27)SBC3" || ver == "12.2(27)SBC4" || ver == "12.2(27)SBC5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SCA
else if (ver == "12.2(33)SCA" || ver == "12.2(33)SCA1" || ver == "12.2(33)SCA2")
  fixed_ver = "12.2(33)SCH2";
#12.2SCB
else if (ver == "12.2(33)SCB" || ver == "12.2(33)SCB1" || ver == "12.2(33)SCB10" || ver == "12.2(33)SCB11" || ver == "12.2(33)SCB2" || ver == "12.2(33)SCB3" || ver == "12.2(33)SCB4" || ver == "12.2(33)SCB5" || ver == "12.2(33)SCB6" || ver == "12.2(33)SCB7" || ver == "12.2(33)SCB8" || ver == "12.2(33)SCB9")
  fixed_ver = "12.2(33)SCH2";
#12.2SCC
else if (ver == "12.2(33)SCC" || ver == "12.2(33)SCC1" || ver == "12.2(33)SCC2" || ver == "12.2(33)SCC3" || ver == "12.2(33)SCC4" || ver == "12.2(33)SCC5" || ver == "12.2(33)SCC6" || ver == "12.2(33)SCC7")
  fixed_ver = "12.2(33)SCH2";
#12.2SCD
else if (ver == "12.2(33)SCD" || ver == "12.2(33)SCD1" || ver == "12.2(33)SCD2" || ver == "12.2(33)SCD3" || ver == "12.2(33)SCD4" || ver == "12.2(33)SCD5" || ver == "12.2(33)SCD6" || ver == "12.2(33)SCD7" || ver == "12.2(33)SCD8")
  fixed_ver = "12.2(33)SCH2";
#12.2SCE
else if (ver == "12.2(33)SCE" || ver == "12.2(33)SCE1" || ver == "12.2(33)SCE2" || ver == "12.2(33)SCE3" || ver == "12.2(33)SCE4" || ver == "12.2(33)SCE5" || ver == "12.2(33)SCE6")
  fixed_ver = "12.2(33)SCH2";
#12.2SCF
else if (ver == "12.2(33)SCF" || ver == "12.2(33)SCF1" || ver == "12.2(33)SCF2" || ver == "12.2(33)SCF3" || ver == "12.2(33)SCF4" || ver == "12.2(33)SCF5")
  fixed_ver = "12.2(33)SCH2";
#12.2SCG
else if (ver == "12.2(33)SCG" || ver == "12.2(33)SCG1" || ver == "12.2(33)SCG2" || ver == "12.2(33)SCG3" || ver == "12.2(33)SCG4" || ver == "12.2(33)SCG5" || ver == "12.2(33)SCG6")
  fixed_ver = "12.2(33)SCH2";
#12.2SCH
else if (ver == "12.2(33)SCH" || ver == "12.2(33)SCH0a" || ver == "12.2(33)SCH1")
  fixed_ver = "12.2(33)SCH2";
#12.2SE
else if (ver == "12.2(18)SE" || ver == "12.2(18)SE1" || ver == "12.2(20)SE" || ver == "12.2(20)SE1" || ver == "12.2(20)SE2" || ver == "12.2(20)SE3" || ver == "12.2(20)SE4" || ver == "12.2(25)SE" || ver == "12.2(25)SE2" || ver == "12.2(25)SE3" || ver == "12.2(35)SE" || ver == "12.2(35)SE1" || ver == "12.2(35)SE2" || ver == "12.2(35)SE3" || ver == "12.2(35)SE4" || ver == "12.2(35)SE5" || ver == "12.2(37)SE" || ver == "12.2(37)SE1" || ver == "12.2(40)SE" || ver == "12.2(44)SE" || ver == "12.2(44)SE1" || ver == "12.2(44)SE2" || ver == "12.2(44)SE3" || ver == "12.2(44)SE4" || ver == "12.2(44)SE5" || ver == "12.2(44)SE6" || ver == "12.2(46)SE" || ver == "12.2(50)SE" || ver == "12.2(50)SE1" || ver == "12.2(50)SE3" || ver == "12.2(50)SE4" || ver == "12.2(50)SE5" || ver == "12.2(52)SE" || ver == "12.2(53)SE" || ver == "12.2(53)SE1" || ver == "12.2(53)SE2" || ver == "12.2(54)SE" || ver == "12.2(55)SE" || ver == "12.2(55)SE1" || ver == "12.2(55)SE2" || ver == "12.2(55)SE3" || ver == "12.2(55)SE4" || ver == "12.2(55)SE5" || ver == "12.2(55)SE6" || ver == "12.2(55)SE7" || ver == "12.2(55)SE8" || ver == "12.2(58)SE" || ver == "12.2(58)SE1" || ver == "12.2(58)SE2")
  fixed_ver = "12.2(55)SE9";
#12.2SEA
else if (ver == "12.2(25)SEA")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SEB
else if (ver == "12.2(25)SEB" || ver == "12.2(25)SEB1" || ver == "12.2(25)SEB2" || ver == "12.2(25)SEB3" || ver == "12.2(25)SEB4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SEC
else if (ver == "12.2(25)SEC" || ver == "12.2(25)SEC1" || ver == "12.2(25)SEC2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SED
else if (ver == "12.2(25)SED" || ver == "12.2(25)SED1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SEE
else if (ver == "12.2(25)SEE" || ver == "12.2(25)SEE1" || ver == "12.2(25)SEE2" || ver == "12.2(25)SEE3" || ver == "12.2(25)SEE4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SEF
else if (ver == "12.2(25)SEF" || ver == "12.2(25)SEF1" || ver == "12.2(25)SEF2" || ver == "12.2(25)SEF3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SEG
else if (ver == "12.2(25)SEG" || ver == "12.2(25)SEG1" || ver == "12.2(25)SEG3")
  fixed_ver = "15.0(2)SE6";
#12.2SG
else if (ver == "12.2(31)SG1" || ver == "12.2(31)SG2" || ver == "12.2(37)SG1")
  fixed_ver = "12.2(40)SG";
#12.2SM
else if (ver == "12.2(29)SM" || ver == "12.2(29)SM1" || ver == "12.2(29)SM2" || ver == "12.2(29)SM3" || ver == "12.2(29)SM4" || ver == "12.2(29)SM5" || ver == "12.2(29)SM6" || ver == "12.2(29)SM7")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SRA
else if (ver == "12.2(33)SRA" || ver == "12.2(33)SRA1" || ver == "12.2(33)SRA2" || ver == "12.2(33)SRA3" || ver == "12.2(33)SRA4" || ver == "12.2(33)SRA5" || ver == "12.2(33)SRA6" || ver == "12.2(33)SRA7")
    fixed_ver = "12.2(33)SRE10";
#12.2SRB
else if (ver == "12.2(33)SRB" || ver == "12.2(33)SRB1" || ver == "12.2(33)SRB2" || ver == "12.2(33)SRB3" || ver == "12.2(33)SRB4" || ver == "12.2(33)SRB5" || ver == "12.2(33)SRB5a" || ver == "12.2(33)SRB6" || ver == "12.2(33)SRB7")
  fixed_ver = "12.2(33)SRE10";
#12.2SRC
else if (ver == "12.2(33)SRC" || ver == "12.2(33)SRC1" || ver == "12.2(33)SRC2" || ver == "12.2(33)SRC3" || ver == "12.2(33)SRC4" || ver == "12.2(33)SRC5" || ver == "12.2(33)SRC6")
  fixed_ver = "12.2(33)SRE10";
#12.2SRD
else if (ver == "12.2(33)SRD" || ver == "12.2(33)SRD1" || ver == "12.2(33)SRD2" || ver == "12.2(33)SRD2a" || ver == "12.2(33)SRD3" || ver == "12.2(33)SRD4" || ver == "12.2(33)SRD4a" || ver == "12.2(33)SRD5" || ver == "12.2(33)SRD6" || ver == "12.2(33)SRD7" || ver == "12.2(33)SRD8")
  fixed_ver = "12.2(33)SRE10";
#12.2SRE
else if (ver == "12.2(33)SRE" || ver == "12.2(33)SRE0a" || ver == "12.2(33)SRE1" || ver == "12.2(33)SRE2" || ver == "12.2(33)SRE3" || ver == "12.2(33)SRE4" || ver == "12.2(33)SRE5" || ver == "12.2(33)SRE6" || ver == "12.2(33)SRE7" || ver == "12.2(33)SRE7a" || ver == "12.2(33)SRE8" || ver == "12.2(33)SRE9" || ver == "12.2(33)SRE9a")
  fixed_ver = "12.2(33)SRE10";
#12.2SU
else if (ver == "12.2(14)SU" || ver == "12.2(14)SU1" || ver == "12.2(14)SU2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SV
else if (ver == "12.2(18)SV3" || ver == "12.2(22)SV1" || ver == "12.2(23)SV1" || ver == "12.2(24)SV1" || ver == "12.2(25)SV2" || ver == "12.2(27)SV5" || ver == "12.2(29)SV3")
  fixed_ver = "12.2(29b)SV1";
#12.2SW
else if (ver == "12.2(18)SW" || ver == "12.2(19)SW" || ver == "12.2(20)SW" || ver == "12.2(21)SW" || ver == "12.2(21)SW1" || ver == "12.2(23)SW" || ver == "12.2(23)SW1" || ver == "12.2(25)SW" || ver == "12.2(25)SW1" || ver == "12.2(25)SW10" || ver == "12.2(25)SW11" || ver == "12.2(25)SW12" || ver == "12.2(25)SW2" || ver == "12.2(25)SW3" || ver == "12.2(25)SW3a" || ver == "12.2(25)SW4" || ver == "12.2(25)SW4a" || ver == "12.2(25)SW5" || ver == "12.2(25)SW6" || ver == "12.2(25)SW7" || ver == "12.2(25)SW8" || ver == "12.2(25)SW9")
  fixed_ver = "15.1(4)M8";
#12.2SX
else if (ver == "12.2(14)SX" || ver == "12.2(14)SX1" || ver == "12.2(14)SX1a" || ver == "12.2(14)SX2" || ver == "12.2(17a)SX" || ver == "12.2(17a)SX1" || ver == "12.2(17a)SX2" || ver == "12.2(17a)SX3" || ver == "12.2(17a)SX4" || ver == "12.2(99)SX1003" || ver == "12.2(99)SX1006" || ver == "12.2(99)SX1010" || ver == "12.2(99)SX1012" || ver == "12.2(99)SX1017")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SXA
else if (ver == "12.2(17b)SXA" || ver == "12.2(17b)SXA1" || ver == "12.2(17b)SXA2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SXB
else if (ver == "12.2(17d)SXB" || ver == "12.2(17d)SXB1" || ver == "12.2(17d)SXB10" || ver == "12.2(17d)SXB11" || ver == "12.2(17d)SXB11a" || ver == "12.2(17d)SXB2" || ver == "12.2(17d)SXB3" || ver == "12.2(17d)SXB4" || ver == "12.2(17d)SXB5" || ver == "12.2(17d)SXB6" || ver == "12.2(17d)SXB7" || ver == "12.2(17d)SXB8" || ver == "12.2(17d)SXB9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SXD
else if (ver == "12.2(18)SXD" || ver == "12.2(18)SXD1" || ver == "12.2(18)SXD2" || ver == "12.2(18)SXD3" || ver == "12.2(18)SXD4" || ver == "12.2(18)SXD5" || ver == "12.2(18)SXD6" || ver == "12.2(18)SXD7" || ver == "12.2(18)SXD7a" || ver == "12.2(18)SXD7b")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SXE
else if (ver == "12.2(18)SXE" || ver == "12.2(18)SXE1" || ver == "12.2(18)SXE2" || ver == "12.2(18)SXE3" || ver == "12.2(18)SXE4" || ver == "12.2(18)SXE5" || ver == "12.2(18)SXE6" || ver == "12.2(18)SXE6a" || ver == "12.2(18)SXE6b")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SXF
else if (ver == "12.2(18)SXF" || ver == "12.2(18)SXF1" || ver == "12.2(18)SXF10" || ver == "12.2(18)SXF10a" || ver == "12.2(18)SXF11" || ver == "12.2(18)SXF12" || ver == "12.2(18)SXF12a" || ver == "12.2(18)SXF13" || ver == "12.2(18)SXF13a" || ver == "12.2(18)SXF13b" || ver == "12.2(18)SXF14" || ver == "12.2(18)SXF15" || ver == "12.2(18)SXF15a" || ver == "12.2(18)SXF16" || ver == "12.2(18)SXF17" || ver == "12.2(18)SXF17a" || ver == "12.2(18)SXF17b" || ver == "12.2(18)SXF2" || ver == "12.2(18)SXF3" || ver == "12.2(18)SXF4" || ver == "12.2(18)SXF5" || ver == "12.2(18)SXF6" || ver == "12.2(18)SXF7" || ver == "12.2(18)SXF8" || ver == "12.2(18)SXF9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SXH
else if (ver == "12.2(33)SXH" || ver == "12.2(33)SXH0a" || ver == "12.2(33)SXH1" || ver == "12.2(33)SXH2" || ver == "12.2(33)SXH2a" || ver == "12.2(33)SXH3" || ver == "12.2(33)SXH3a" || ver == "12.2(33)SXH4" || ver == "12.2(33)SXH5" || ver == "12.2(33)SXH6" || ver == "12.2(33)SXH7" || ver == "12.2(33)SXH7v" || ver == "12.2(33)SXH7w" || ver == "12.2(33)SXH8" || ver == "12.2(33)SXH8a" || ver == "12.2(33)SXH8b")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2SXI
else if (ver == "12.2(33)SXI" || ver == "12.2(33)SXI1" || ver == "12.2(33)SXI10" || ver == "12.2(33)SXI11" || ver == "12.2(33)SXI12" || ver == "12.2(33)SXI2" || ver == "12.2(33)SXI2a" || ver == "12.2(33)SXI3" || ver == "12.2(33)SXI3a" || ver == "12.2(33)SXI3z" || ver == "12.2(33)SXI4" || ver == "12.2(33)SXI4a" || ver == "12.2(33)SXI5" || ver == "12.2(33)SXI5a" || ver == "12.2(33)SXI6" || ver == "12.2(33)SXI7" || ver == "12.2(33)SXI8" || ver == "12.2(33)SXI8a" || ver == "12.2(33)SXI9" || ver == "12.2(33)SXI9a")
  fixed_ver = "12.2(33)SXI13";
#12.2SXJ
else if (ver == "12.2(33)SXJ" || ver == "12.2(33)SXJ1" || ver == "12.2(33)SXJ2" || ver == "12.2(33)SXJ3" || ver == "12.2(33)SXJ4" || ver == "12.2(33)SXJ5" || ver == "12.2(33)SXJ6")
  fixed_ver = "12.2(33)SXJ7";
#12.2SY
else if (ver == "12.2(14)SY" || ver == "12.2(14)SY1" || ver == "12.2(14)SY2" || ver == "12.2(14)SY3" || ver == "12.2(14)SY4" || ver == "12.2(14)SY5" || ver == "12.2(50)SY" || ver == "12.2(50)SY1" || ver == "12.2(50)SY2" || ver == "12.2(50)SY3" || ver == "12.2(50)SY4")
  fixed_ver = "15.0(1)SY6";
#12.2SZ
else if (ver == "12.2(14)SZ" || ver == "12.2(14)SZ1" || ver == "12.2(14)SZ2" || ver == "12.2(14)SZ3" || ver == "12.2(14)SZ4" || ver == "12.2(14)SZ5" || ver == "12.2(14)SZ6")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2T
else if (ver == "12.2(2)T" || ver == "12.2(2)T1" || ver == "12.2(2)T2" || ver == "12.2(2)T3" || ver == "12.2(2)T4" || ver == "12.2(4)T" || ver == "12.2(4)T1" || ver == "12.2(4)T2" || ver == "12.2(4)T3" || ver == "12.2(4)T4" || ver == "12.2(4)T5" || ver == "12.2(4)T6" || ver == "12.2(4)T7" || ver == "12.2(8)T" || ver == "12.2(8)T0a" || ver == "12.2(8)T0b" || ver == "12.2(8)T0c" || ver == "12.2(8)T0d" || ver == "12.2(8)T0e" || ver == "12.2(8)T1" || ver == "12.2(8)T10" || ver == "12.2(8)T2" || ver == "12.2(8)T3" || ver == "12.2(8)T4" || ver == "12.2(8)T4a" || ver == "12.2(8)T5" || ver == "12.2(8)T6" || ver == "12.2(8)T7" || ver == "12.2(8)T8" || ver == "12.2(8)T9" || ver == "12.2(11)T" || ver == "12.2(11)T1" || ver == "12.2(11)T10" || ver == "12.2(11)T11" || ver == "12.2(11)T2" || ver == "12.2(11)T3" || ver == "12.2(11)T4" || ver == "12.2(11)T5" || ver == "12.2(11)T6" || ver == "12.2(11)T7" || ver == "12.2(11)T8" || ver == "12.2(11)T9" || ver == "12.2(13)T" || ver == "12.2(13)T1" || ver == "12.2(13)T1a" || ver == "12.2(13)T10" || ver == "12.2(13)T11" || ver == "12.2(13)T12" || ver == "12.2(13)T13" || ver == "12.2(13)T14" || ver == "12.2(13)T15" || ver == "12.2(13)T16" || ver == "12.2(13)T17" || ver == "12.2(13)T2" || ver == "12.2(13)T3" || ver == "12.2(13)T4" || ver == "12.2(13)T5" || ver == "12.2(13)T6" || ver == "12.2(13)T7" || ver == "12.2(13)T8" || ver == "12.2(13)T8a" || ver == "12.2(13)T9" || ver == "12.2(15)T" || ver == "12.2(15)T1" || ver == "12.2(15)T1a" || ver == "12.2(15)T10" || ver == "12.2(15)T11" || ver == "12.2(15)T12" || ver == "12.2(15)T12a" || ver == "12.2(15)T13" || ver == "12.2(15)T14" || ver == "12.2(15)T15" || ver == "12.2(15)T16" || ver == "12.2(15)T17" || ver == "12.2(15)T2" || ver == "12.2(15)T3" || ver == "12.2(15)T4" || ver == "12.2(15)T4a" || ver == "12.2(15)T4c" || ver == "12.2(15)T4d" || ver == "12.2(15)T4e" || ver == "12.2(15)T5" || ver == "12.2(15)T5a" || ver == "12.2(15)T6" || ver == "12.2(15)T7" || ver == "12.2(15)T8" || ver == "12.2(15)T9" || ver == "12.2(15)T9a" || ver == "12.2(15)T9b")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2tpc
else if (ver == "12.2(8)TPC10a" || ver == "12.2(8)TPC10b" || ver == "12.2(8)TPC10c")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XA
else if (ver == "12.2(2)XA" || ver == "12.2(2)XA1" || ver == "12.2(2)XA2" || ver == "12.2(2)XA3" || ver == "12.2(2)XA4" || ver == "12.2(2)XA5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XB
else if (ver == "12.2(2)XB1" || ver == "12.2(2)XB10" || ver == "12.2(2)XB11" || ver == "12.2(2)XB12" || ver == "12.2(2)XB14" || ver == "12.2(2)XB15" || ver == "12.2(2)XB16" || ver == "12.2(2)XB17" || ver == "12.2(2)XB18" || ver == "12.2(2)XB2" || ver == "12.2(2)XB3" || ver == "12.2(2)XB4" || ver == "12.2(2)XB4b" || ver == "12.2(2)XB5" || ver == "12.2(2)XB6" || ver == "12.2(2)XB7" || ver == "12.2(2)XB8" || ver == "12.2(2)XB9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XC
else if (ver == "12.2(1a)XC" || ver == "12.2(1a)XC1" || ver == "12.2(1a)XC2" || ver == "12.2(1a)XC3" || ver == "12.2(1a)XC4" || ver == "12.2(1a)XC5" || ver == "12.2(2)XC" || ver == "12.2(2)XC1" || ver == "12.2(2)XC2" || ver == "12.2(2)XC3" || ver == "12.2(2)XC4" || ver == "12.2(2)XC5" || ver == "12.2(2)XC6" || ver == "12.2(2)XC7")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XD
else if (ver == "12.2(1)XD" || ver == "12.2(1)XD1" || ver == "12.2(1)XD2" || ver == "12.2(1)XD3" || ver == "12.2(1)XD4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XF
else if (ver == "12.2(4)XF1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XG
else if (ver == "12.2(2)XG")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XH
else if (ver == "12.2(2)XH" || ver == "12.2(2)XH1" || ver == "12.2(2)XH2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XI
else if (ver == "12.2(2)XI" || ver == "12.2(2)XI1" || ver == "12.2(2)XI2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XJ
else if (ver == "12.2(2)XJ")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XK
else if (ver == "12.2(2)XK" || ver == "12.2(2)XK1" || ver == "12.2(2)XK2" || ver == "12.2(2)XK3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XL
else if (ver == "12.2(4)XL" || ver == "12.2(4)XL1" || ver == "12.2(4)XL2" || ver == "12.2(4)XL3" || ver == "12.2(4)XL4" || ver == "12.2(4)XL5" || ver == "12.2(4)XL6")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XM
else if (ver == "12.2(4)XM" || ver == "12.2(4)XM1" || ver == "12.2(4)XM2" || ver == "12.2(4)XM3" || ver == "12.2(4)XM4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XN
else if (ver == "12.2(2)XN" || ver == "12.2(31)XN" || ver == "12.2(31)XN1" || ver == "12.2(31)XN2" || ver == "12.2(31)XN3" || ver == "12.2(31a)XN2" || ver == "12.2(31a)XN3" || ver == "12.2(31b)XN2" || ver == "12.2(31b)XN3" || ver == "12.2(31c)XN2" || ver == "12.2(31c)XN3" || ver == "12.2(33)XN" || ver == "12.2(33)XN1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XQ
else if (ver == "12.2(2)XQ" || ver == "12.2(2)XQ1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XR
else if (ver == "12.2(2)XR" || ver == "12.2(4)XR")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XS
else if (ver == "12.2(1)XS" || ver == "12.2(1)XS1" || ver == "12.2(1)XS1a" || ver == "12.2(1)XS2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XT
else if (ver == "12.2(2)XT" || ver == "12.2(2)XT2" || ver == "12.2(2)XT3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XU
else if (ver == "12.2(2)XU" || ver == "12.2(2)XU2" || ver == "12.2(2)XU3" || ver == "12.2(2)XU4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XV
else if (ver == "12.2(4)XV" || ver == "12.2(4)XV1" || ver == "12.2(4)XV2" || ver == "12.2(4)XV3" || ver == "12.2(4)XV4" || ver == "12.2(4)XV4a" || ver == "12.2(4)XV5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XW
else if (ver == "12.2(4)XW")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2XZ
else if (ver == "12.2(4)XZ" || ver == "12.2(4)XZ1" || ver == "12.2(4)XZ2" || ver == "12.2(4)XZ3" || ver == "12.2(4)XZ4" || ver == "12.2(4)XZ5" || ver == "12.2(4)XZ6" || ver == "12.2(4)XZ7")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YA
else if (ver == "12.2(4)YA" || ver == "12.2(4)YA1" || ver == "12.2(4)YA10" || ver == "12.2(4)YA11" || ver == "12.2(4)YA12" || ver == "12.2(4)YA2" || ver == "12.2(4)YA3" || ver == "12.2(4)YA4" || ver == "12.2(4)YA5" || ver == "12.2(4)YA6" || ver == "12.2(4)YA7" || ver == "12.2(4)YA8" || ver == "12.2(4)YA9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YB
else if (ver == "12.2(4)YB")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YC
else if (ver == "12.2(2)YC" || ver == "12.2(2)YC1" || ver == "12.2(2)YC2" || ver == "12.2(2)YC3" || ver == "12.2(2)YC4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YD
else if (ver == "12.2(8)YD" || ver == "12.2(8)YD1" || ver == "12.2(8)YD2" || ver == "12.2(8)YD3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YE
else if (ver == "12.2(9)YE")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YF
else if (ver == "12.2(4)YF")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YG
else if (ver == "12.2(4)YG")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YH
else if (ver == "12.2(4)YH")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YJ
else if (ver == "12.2(8)YJ" || ver == "12.2(8)YJ1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YL
else if (ver == "12.2(8)YL")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YM
else if (ver == "12.2(8)YM")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YN
else if (ver == "12.2(8)YN" || ver == "12.2(8)YN1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YQ
else if (ver == "12.2(11)YQ")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YR
else if (ver == "12.2(11)YR")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YT
else if (ver == "12.2(11)YT" || ver == "12.2(11)YT1" || ver == "12.2(11)YT2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YU
else if (ver == "12.2(11)YU")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YV
else if (ver == "12.2(11)YV" || ver == "12.2(11)YV1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YW
else if (ver == "12.2(8)YW" || ver == "12.2(8)YW1" || ver == "12.2(8)YW2" || ver == "12.2(8)YW3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YX
else if (ver == "12.2(11)YX" || ver == "12.2(11)YX1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YY
else if (ver == "12.2(8)YY" || ver == "12.2(8)YY1" || ver == "12.2(8)YY2" || ver == "12.2(8)YY3" || ver == "12.2(8)YY4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2YZ
else if (ver == "12.2(11)YZ" || ver == "12.2(11)YZ1" || ver == "12.2(11)YZ2" || ver == "12.2(11)YZ3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZA
else if (ver == "12.2(9)ZA" || ver == "12.2(14)ZA" || ver == "12.2(14)ZA1" || ver == "12.2(14)ZA2" || ver == "12.2(14)ZA3" || ver == "12.2(14)ZA4" || ver == "12.2(14)ZA5" || ver == "12.2(14)ZA6" || ver == "12.2(14)ZA7")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZB
else if (ver == "12.2(8)ZB" || ver == "12.2(8)ZB1" || ver == "12.2(8)ZB2" || ver == "12.2(8)ZB3" || ver == "12.2(8)ZB4" || ver == "12.2(8)ZB4a" || ver == "12.2(8)ZB5" || ver == "12.2(8)ZB6" || ver == "12.2(8)ZB7" || ver == "12.2(8)ZB8")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZD
else if (ver == "12.2(13)ZD" || ver == "12.2(13)ZD1" || ver == "12.2(13)ZD2" || ver == "12.2(13)ZD3" || ver == "12.2(13)ZD4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZE
else if (ver == "12.2(13)ZE")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZF
else if (ver == "12.2(13)ZF" || ver == "12.2(13)ZF1" || ver == "12.2(13)ZF2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZG
else if (ver == "12.2(13)ZG")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZH
else if (ver == "12.2(13)ZH" || ver == "12.2(13)ZH1" || ver == "12.2(13)ZH10" || ver == "12.2(13)ZH2" || ver == "12.2(13)ZH3" || ver == "12.2(13)ZH4" || ver == "12.2(13)ZH5" || ver == "12.2(13)ZH6" || ver == "12.2(13)ZH7" || ver == "12.2(13)ZH8" || ver == "12.2(13)ZH9")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZI
else if (ver == "12.2(33)ZI")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZJ
else if (ver == "12.2(15)ZJ" || ver == "12.2(15)ZJ1" || ver == "12.2(15)ZJ2" || ver == "12.2(15)ZJ3" || ver == "12.2(15)ZJ4" || ver == "12.2(15)ZJ5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZK
else if (ver == "12.2(15)ZK" || ver == "12.2(15)ZK1" || ver == "12.2(15)ZK2" || ver == "12.2(15)ZK3" || ver == "12.2(15)ZK4" || ver == "12.2(15)ZK5" || ver == "12.2(15)ZK6")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZL
else if (ver == "12.2(15)ZL" || ver == "12.2(15)ZL1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZN
else if (ver == "12.2(15)ZN")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZO
else if (ver == "12.2(15)ZO")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZQ
else if (ver == "12.2(21)ZQ" || ver == "12.2(21)ZQ2" || ver == "12.2(21)ZQ3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZR
else if (ver == "12.2(15)ZR")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZS
else if (ver == "12.2(15)ZS1" || ver == "12.2(15)ZS2" || ver == "12.2(15)ZS3" || ver == "12.2(15)ZS4" || ver == "12.2(15)ZS5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZT
else if (ver == "12.2(13)ZT")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZU
else if (ver == "12.2(18)ZU" || ver == "12.2(18)ZU1" || ver == "12.2(18)ZU2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZV
else if (ver == "12.2(28)ZV" || ver == "12.2(28)ZV1" || ver == "12.2(31)ZV0c")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZW
else if (ver == "12.2(33)ZW")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZY
else if (ver == "12.2(18)ZY" || ver == "12.2(18)ZY1" || ver == "12.2(18)ZY2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZYA
else if (ver == "12.2(18)ZYA" || ver == "12.2(18)ZYA1" || ver == "12.2(18)ZYA2" || ver == "12.2(18)ZYA3" || ver == "12.2(18)ZYA3a" || ver == "12.2(18)ZYA3b" || ver == "12.2(18)ZYA3c")
  fixed_ver = "Refer to the vendor for a fix.";
#12.2ZZ
else if (ver == "12.2(33)ZZ")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3
else if (ver == "12.3(1)" || ver == "12.3(1a)" || ver == "12.3(3)" || ver == "12.3(3a)" || ver == "12.3(3b)" || ver == "12.3(3c)" || ver == "12.3(3d)" || ver == "12.3(3e)" || ver == "12.3(3f)" || ver == "12.3(3g)" || ver == "12.3(3h)" || ver == "12.3(3i)" || ver == "12.3(5)" || ver == "12.3(5a)" || ver == "12.3(5b)" || ver == "12.3(5c)" || ver == "12.3(5d)" || ver == "12.3(5e)" || ver == "12.3(5f)" || ver == "12.3(6)" || ver == "12.3(6a)" || ver == "12.3(6b)" || ver == "12.3(6c)" || ver == "12.3(6d)" || ver == "12.3(6e)" || ver == "12.3(6f)" || ver == "12.3(9)" || ver == "12.3(9a)" || ver == "12.3(9b)" || ver == "12.3(9c)" || ver == "12.3(9d)" || ver == "12.3(9e)" || ver == "12.3(10)" || ver == "12.3(10a)" || ver == "12.3(10b)" || ver == "12.3(10c)" || ver == "12.3(10d)" || ver == "12.3(10e)" || ver == "12.3(10f)" || ver == "12.3(12)" || ver == "12.3(12a)" || ver == "12.3(12b)" || ver == "12.3(12c)" || ver == "12.3(12d)" || ver == "12.3(12e)" || ver == "12.3(13)" || ver == "12.3(13a)" || ver == "12.3(13b)" || ver == "12.3(15)" || ver == "12.3(15a)" || ver == "12.3(15b)" || ver == "12.3(16)" || ver == "12.3(16a)" || ver == "12.3(17)" || ver == "12.3(17a)" || ver == "12.3(17b)" || ver == "12.3(17c)" || ver == "12.3(18)" || ver == "12.3(18a)" || ver == "12.3(19)" || ver == "12.3(19a)" || ver == "12.3(20)" || ver == "12.3(20a)" || ver == "12.3(21)" || ver == "12.3(21a)" || ver == "12.3(21b)" || ver == "12.3(22)" || ver == "12.3(22a)" || ver == "12.3(23)" || ver == "12.3(24)" || ver == "12.3(24a)" || ver == "12.3(25)" || ver == "12.3(26)")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3B
else if (ver == "12.3(1a)B" || ver == "12.3(3)B" || ver == "12.3(3)B1" || ver == "12.3(5a)B" || ver == "12.3(5a)B0a" || ver == "12.3(5a)B1" || ver == "12.3(5a)B2" || ver == "12.3(5a)B3" || ver == "12.3(5a)B4" || ver == "12.3(5a)B5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3BC
else if (ver == "12.3(9a)BC" || ver == "12.3(9a)BC1" || ver == "12.3(9a)BC2" || ver == "12.3(9a)BC3" || ver == "12.3(9a)BC4" || ver == "12.3(9a)BC5" || ver == "12.3(9a)BC6" || ver == "12.3(9a)BC7" || ver == "12.3(9a)BC8" || ver == "12.3(9a)BC9" || ver == "12.3(13a)BC" || ver == "12.3(13a)BC1" || ver == "12.3(13a)BC2" || ver == "12.3(13a)BC3" || ver == "12.3(13a)BC4" || ver == "12.3(13a)BC5" || ver == "12.3(13a)BC6" || ver == "12.3(17a)BC" || ver == "12.3(17a)BC1" || ver == "12.3(17a)BC2" || ver == "12.3(17b)BC3" || ver == "12.3(17b)BC4" || ver == "12.3(17b)BC5" || ver == "12.3(17b)BC6" || ver == "12.3(17b)BC7" || ver == "12.3(17b)BC8" || ver == "12.3(17b)BC9" || ver == "12.3(21)BC" || ver == "12.3(21a)BC1" || ver == "12.3(21a)BC2" || ver == "12.3(21a)BC3" || ver == "12.3(21a)BC4" || ver == "12.3(21a)BC5" || ver == "12.3(21a)BC6" || ver == "12.3(21a)BC7" || ver == "12.3(21a)BC8" || ver == "12.3(21a)BC9" || ver == "12.3(23)BC" || ver == "12.3(23)BC1" || ver == "12.3(23)BC10" || ver == "12.3(23)BC2" || ver == "12.3(23)BC3" || ver == "12.3(23)BC4" || ver == "12.3(23)BC5" || ver == "12.3(23)BC6" || ver == "12.3(23)BC7" || ver == "12.3(23)BC8" || ver == "12.3(23)BC9")
  fixed_ver = "12.2(33)SCH2";
#12.3BW
else if (ver == "12.3(1a)BW")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3M
else if (ver == "12.3(9)M0" || ver == "12.3(9)M1" || ver == "12.3(10a)M0")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3T
else if (ver == "12.3(2)T" || ver == "12.3(2)T1" || ver == "12.3(2)T2" || ver == "12.3(2)T3" || ver == "12.3(2)T4" || ver == "12.3(2)T5" || ver == "12.3(2)T6" || ver == "12.3(2)T7" || ver == "12.3(2)T8" || ver == "12.3(2)T9" || ver == "12.3(4)T" || ver == "12.3(4)T1" || ver == "12.3(4)T10" || ver == "12.3(4)T11" || ver == "12.3(4)T12" || ver == "12.3(4)T2" || ver == "12.3(4)T2a" || ver == "12.3(4)T3" || ver == "12.3(4)T4" || ver == "12.3(4)T5" || ver == "12.3(4)T6" || ver == "12.3(4)T7" || ver == "12.3(4)T8" || ver == "12.3(4)T9" || ver == "12.3(7)T" || ver == "12.3(7)T1" || ver == "12.3(7)T10" || ver == "12.3(7)T11" || ver == "12.3(7)T12" || ver == "12.3(7)T2" || ver == "12.3(7)T3" || ver == "12.3(7)T4" || ver == "12.3(7)T5" || ver == "12.3(7)T6" || ver == "12.3(7)T7" || ver == "12.3(7)T8" || ver == "12.3(7)T9" || ver == "12.3(8)T" || ver == "12.3(8)T0a" || ver == "12.3(8)T1" || ver == "12.3(8)T10" || ver == "12.3(8)T11" || ver == "12.3(8)T2" || ver == "12.3(8)T3" || ver == "12.3(8)T4" || ver == "12.3(8)T5" || ver == "12.3(8)T6" || ver == "12.3(8)T7" || ver == "12.3(8)T8" || ver == "12.3(8)T9" || ver == "12.3(11)T" || ver == "12.3(11)T1" || ver == "12.3(11)T10" || ver == "12.3(11)T11" || ver == "12.3(11)T12" || ver == "12.3(11)T2" || ver == "12.3(11)T2a" || ver == "12.3(11)T3" || ver == "12.3(11)T4" || ver == "12.3(11)T5" || ver == "12.3(11)T6" || ver == "12.3(11)T7" || ver == "12.3(11)T8" || ver == "12.3(11)T9" || ver == "12.3(14)T" || ver == "12.3(14)T1" || ver == "12.3(14)T2" || ver == "12.3(14)T3" || ver == "12.3(14)T4" || ver == "12.3(14)T5" || ver == "12.3(14)T6" || ver == "12.3(14)T7")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3TO
else if (ver == "12.3(11)TO3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3TPC
else if (ver == "12.3(4)TPC11a" || ver == "12.3(4)TPC11b")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XA
else if (ver == "12.3(2)XA" || ver == "12.3(2)XA1" || ver == "12.3(2)XA2" || ver == "12.3(2)XA3" || ver == "12.3(2)XA4" || ver == "12.3(2)XA5" || ver == "12.3(2)XA6" || ver == "12.3(2)XA7")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XB
else if (ver == "12.3(2)XB" || ver == "12.3(2)XB1" || ver == "12.3(2)XB3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XC
else if (ver == "12.3(2)XC" || ver == "12.3(2)XC1" || ver == "12.3(2)XC2" || ver == "12.3(2)XC3" || ver == "12.3(2)XC4" || ver == "12.3(2)XC5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XD
else if (ver == "12.3(4)XD" || ver == "12.3(4)XD1" || ver == "12.3(4)XD2" || ver == "12.3(4)XD3" || ver == "12.3(4)XD4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XE
else if (ver == "12.3(2)XE" || ver == "12.3(2)XE1" || ver == "12.3(2)XE2" || ver == "12.3(2)XE3" || ver == "12.3(2)XE4" || ver == "12.3(2)XE5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XF
else if (ver == "12.3(2)XF")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XG
else if (ver == "12.3(4)XG" || ver == "12.3(4)XG1" || ver == "12.3(4)XG2" || ver == "12.3(4)XG3" || ver == "12.3(4)XG4" || ver == "12.3(4)XG5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XH
else if (ver == "12.3(4)XH" || ver == "12.3(4)XH1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XI
else if (ver == "12.3(7)XI" || ver == "12.3(7)XI10a" || ver == "12.3(7)XI2" || ver == "12.3(7)XI2b" || ver == "12.3(7)XI3" || ver == "12.3(7)XI4" || ver == "12.3(7)XI5" || ver == "12.3(7)XI6" || ver == "12.3(7)XI7" || ver == "12.3(7)XI7a" || ver == "12.3(7)XI7b" || ver == "12.3(7)XI8" || ver == "12.3(7)XI8bc" || ver == "12.3(7)XI8g")
  fixed_ver = "12.2(33)SRE10";
#12.3XJ
else if (ver == "12.3(7)XJ" || ver == "12.3(7)XJ1" || ver == "12.3(7)XJ2")
  fixed_ver = "15.1(4)M8";
#12.3XK
else if (ver == "12.3(4)XK" || ver == "12.3(4)XK1" || ver == "12.3(4)XK2" || ver == "12.3(4)XK3" || ver == "12.3(4)XK4")
  fixed_ver = "15.1(4)M8";
#12.3XL
else if (ver == "12.3(7)XL" || ver == "12.3(11)XL" || ver == "12.3(11)XL1" || ver == "12.3(11)XL2" || ver == "12.3(11)XL3")
  fixed_ver = "15.1(4)M8";
#12.3XM
else if (ver == "12.3(7)XM")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XQ
else if (ver == "12.3(4)XQ" || ver == "12.3(4)XQ1")
  fixed_ver = "15.1(4)M8";
#12.3XR
else if (ver == "12.3(7)XR" || ver == "12.3(7)XR1" || ver == "12.3(7)XR2" || ver == "12.3(7)XR3" || ver == "12.3(7)XR4" || ver == "12.3(7)XR5" || ver == "12.3(7)XR6" || ver == "12.3(7)XR7")
  fixed_ver = "15.1(4)M8";
#12.3XS
else if (ver == "12.3(7)XS" || ver == "12.3(7)XS1" || ver == "12.3(7)XS2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3XU
else if (ver == "12.3(8)XU" || ver == "12.3(8)XU1" || ver == "12.3(8)XU2" || ver == "12.3(8)XU3" || ver == "12.3(8)XU4" || ver == "12.3(8)XU5")
  fixed_ver = "15.1(4)M8";
#12.3XW
else if (ver == "12.3(8)XW" || ver == "12.3(8)XW1" || ver == "12.3(8)XW1a" || ver == "12.3(8)XW1b" || ver == "12.3(8)XW2" || ver == "12.3(8)XW3")
  fixed_ver = "15.1(4)M8";
#12.3XX
else if (ver == "12.3(8)XX" || ver == "12.3(8)XX1" || ver == "12.3(8)XX2" || ver == "12.3(8)XX2a" || ver == "12.3(8)XX2b" || ver == "12.3(8)XX2c" || ver == "12.3(8)XX2d" || ver == "12.3(8)XX2e")
  fixed_ver = "15.1(4)M8";
#12.3XZ
else if (ver == "12.3(2)XZ1" || ver == "12.3(2)XZ2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YA
else if (ver == "12.3(8)YA" || ver == "12.3(8)YA1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YB
else if (ver == "12.3(7)YB" || ver == "12.3(7)YB1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YC
else if (ver == "12.3(8)YC" || ver == "12.3(8)YC1" || ver == "12.3(8)YC2" || ver == "12.3(8)YC3")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YD
else if (ver == "12.3(8)YD" || ver == "12.3(8)YD1")
  fixed_ver = "15.1(4)M8";
#12.3YE
else if (ver == "12.3(4)YE" || ver == "12.3(4)YE1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YF
else if (ver == "12.3(11)YF" || ver == "12.3(11)YF1" || ver == "12.3(11)YF2" || ver == "12.3(11)YF3" || ver == "12.3(11)YF4")
  fixed_ver = "15.1(4)M8";
#12.3YG
else if (ver == "12.3(8)YG" || ver == "12.3(8)YG1" || ver == "12.3(8)YG2" || ver == "12.3(8)YG3" || ver == "12.3(8)YG4" || ver == "12.3(8)YG5" || ver == "12.3(8)YG6" || ver == "12.3(8)YG7")
  fixed_ver = "15.1(4)M8";
#12.3YH
else if (ver == "12.3(8)YH")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YI
else if (ver == "12.3(8)YI" || ver == "12.3(8)YI1" || ver == "12.3(8)YI2" || ver == "12.3(8)YI3")
  fixed_ver = "15.1(4)M8";
#12.3YJ
else if (ver == "12.3(11)YJ")
  fixed_ver = "15.1(4)M8";
#12.3YK
else if (ver == "12.3(11)YK" || ver == "12.3(11)YK1" || ver == "12.3(11)YK2" || ver == "12.3(11)YK3")
  fixed_ver = "15.1(4)M8";
#12.3YL
else if (ver == "12.3(11)YL" || ver == "12.3(11)YL1" || ver == "12.3(11)YL2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YM
else if (ver == "12.3(14)YM1" || ver == "12.3(14)YM10" || ver == "12.3(14)YM11" || ver == "12.3(14)YM12" || ver == "12.3(14)YM13" || ver == "12.3(14)YM2" || ver == "12.3(14)YM3" || ver == "12.3(14)YM4" || ver == "12.3(14)YM5" || ver == "12.3(14)YM6" || ver == "12.3(14)YM7" || ver == "12.3(14)YM8" || ver == "12.3(14)YM9")
  fixed_ver = "15.1(4)M8";
#12.3YN
else if (ver == "12.3(11)YN")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YQ
else if (ver == "12.3(14)YQ" || ver == "12.3(14)YQ1" || ver == "12.3(14)YQ2" || ver == "12.3(14)YQ3" || ver == "12.3(14)YQ4" || ver == "12.3(14)YQ5" || ver == "12.3(14)YQ6" || ver == "12.3(14)YQ7" || ver == "12.3(14)YQ8")
  fixed_ver = "15.1(4)M8";
#12.3YR
else if (ver == "12.3(11)YR" || ver == "12.3(11)YR1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3YS
else if (ver == "12.3(11)YS" || ver == "12.3(11)YS1" || ver == "12.3(11)YS2")
  fixed_ver = "15.1(4)M8";
#12.3YT
else if (ver == "12.3(14)YT" || ver == "12.3(14)YT1")
  fixed_ver = "15.1(4)M8";
#12.3YU
else if (ver == "12.3(14)YU" || ver == "12.3(14)YU1")
  fixed_ver = "15.1(4)M8";
#12.3YX
else if (ver == "12.3(14)YX" || ver == "12.3(14)YX1" || ver == "12.3(14)YX10" || ver == "12.3(14)YX11" || ver == "12.3(14)YX12" || ver == "12.3(14)YX13" || ver == "12.3(14)YX14" || ver == "12.3(14)YX15" || ver == "12.3(14)YX16" || ver == "12.3(14)YX17" || ver == "12.3(14)YX2" || ver == "12.3(14)YX3" || ver == "12.3(14)YX4" || ver == "12.3(14)YX7" || ver == "12.3(14)YX8" || ver == "12.3(14)YX9")
  fixed_ver = "15.1(4)M8";
#12.3YZ
else if (ver == "12.3(11)YZ" || ver == "12.3(11)YZ1" || ver == "12.3(11)YZ2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.3ZA
else if (ver == "12.3(8)ZA" || ver == "12.3(8)ZA1")
  fixed_ver = "15.1(4)M8";
#12.3ZB
else if (ver == "12.3(11)ZB" || ver == "12.3(11)ZB1" || ver == "12.3(11)ZB2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4
else if (ver == "12.4(1)" || ver == "12.4(1a)" || ver == "12.4(1b)" || ver == "12.4(1c)" || ver == "12.4(3)" || ver == "12.4(3a)" || ver == "12.4(3b)" || ver == "12.4(3c)" || ver == "12.4(3d)" || ver == "12.4(3e)" || ver == "12.4(3f)" || ver == "12.4(3g)" || ver == "12.4(3h)" || ver == "12.4(3i)" || ver == "12.4(3j)" || ver == "12.4(5)" || ver == "12.4(5a)" || ver == "12.4(5b)" || ver == "12.4(5c)" || ver == "12.4(7)" || ver == "12.4(7a)" || ver == "12.4(7b)" || ver == "12.4(7c)" || ver == "12.4(7d)" || ver == "12.4(7e)" || ver == "12.4(7f)" || ver == "12.4(7g)" || ver == "12.4(7h)" || ver == "12.4(8)" || ver == "12.4(8a)" || ver == "12.4(8b)" || ver == "12.4(8c)" || ver == "12.4(8d)" || ver == "12.4(10)" || ver == "12.4(10a)" || ver == "12.4(10b)" || ver == "12.4(10c)" || ver == "12.4(12)" || ver == "12.4(12a)" || ver == "12.4(12b)" || ver == "12.4(12c)" || ver == "12.4(13)" || ver == "12.4(13a)" || ver == "12.4(13b)" || ver == "12.4(13c)" || ver == "12.4(13d)" || ver == "12.4(13e)" || ver == "12.4(13f)" || ver == "12.4(16)" || ver == "12.4(16a)" || ver == "12.4(16b)" || ver == "12.4(17)" || ver == "12.4(17a)" || ver == "12.4(17b)" || ver == "12.4(18)" || ver == "12.4(18a)" || ver == "12.4(18b)" || ver == "12.4(18c)" || ver == "12.4(18d)" || ver == "12.4(18e)" || ver == "12.4(19)" || ver == "12.4(21)" || ver == "12.4(21a)" || ver == "12.4(23)" || ver == "12.4(23a)" || ver == "12.4(23b)" || ver == "12.4(23c)" || ver == "12.4(23d)" || ver == "12.4(23e)" || ver == "12.4(25)" || ver == "12.4(25a)" || ver == "12.4(25b)" || ver == "12.4(25c)" || ver == "12.4(25d)" || ver == "12.4(25e)" || ver == "12.4(25f)" || ver == "12.4(25g)")
  fixed_ver = "15.1(4)M8";
#12.4GC
else if (ver == "12.4(22)GC1" || ver == "12.4(22)GC1a" || ver == "12.4(24)GC1" || ver == "12.4(24)GC3" || ver == "12.4(24)GC3a" || ver == "12.4(24)GC4" || ver == "12.4(24)GC5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4M
else if (ver == "12.4(5a)M0" || ver == "12.4(21a)M1" || ver == "12.4(23b)M1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4MD
else if (ver == "12.4(11)MD" || ver == "12.4(11)MD1" || ver == "12.4(11)MD10" || ver == "12.4(11)MD2" || ver == "12.4(11)MD3" || ver == "12.4(11)MD4" || ver == "12.4(11)MD5" || ver == "12.4(11)MD6" || ver == "12.4(11)MD7" || ver == "12.4(11)MD8" || ver == "12.4(11)MD9" || ver == "12.4(15)MD" || ver == "12.4(15)MD1" || ver == "12.4(15)MD2" || ver == "12.4(15)MD3" || ver == "12.4(15)MD4" || ver == "12.4(15)MD5" || ver == "12.4(22)MD" || ver == "12.4(22)MD1" || ver == "12.4(22)MD2" || ver == "12.4(24)MD" || ver == "12.4(24)MD1" || ver == "12.4(24)MD2" || ver == "12.4(24)MD3" || ver == "12.4(24)MD4" || ver == "12.4(24)MD5" || ver == "12.4(24)MD6" || ver == "12.4(24)MD7")
  fixed_ver = "12.4(24)MDB17";
#12.4MDA
else if (ver == "12.4(22)MDA" || ver == "12.4(22)MDA1" || ver == "12.4(22)MDA2" || ver == "12.4(22)MDA3" || ver == "12.4(22)MDA4" || ver == "12.4(22)MDA5" || ver == "12.4(22)MDA6" || ver == "12.4(24)MDA" || ver == "12.4(24)MDA1" || ver == "12.4(24)MDA10" || ver == "12.4(24)MDA11" || ver == "12.4(24)MDA12" || ver == "12.4(24)MDA13" || ver == "12.4(24)MDA2" || ver == "12.4(24)MDA3" || ver == "12.4(24)MDA4" || ver == "12.4(24)MDA5" || ver == "12.4(24)MDA6" || ver == "12.4(24)MDA7" || ver == "12.4(24)MDA8" || ver == "12.4(24)MDA9")
  fixed_ver = "12.4(24)MDB17";
#12.4MDB
else if (ver == "12.4(24)MDB" || ver == "12.4(24)MDB1" || ver == "12.4(24)MDB10" || ver == "12.4(24)MDB11" || ver == "12.4(24)MDB12" || ver == "12.4(24)MDB13" || ver == "12.4(24)MDB14" || ver == "12.4(24)MDB15" || ver == "12.4(24)MDB16" || ver == "12.4(24)MDB3" || ver == "12.4(24)MDB4" || ver == "12.4(24)MDB5" || ver == "12.4(24)MDB5a" || ver == "12.4(24)MDB6" || ver == "12.4(24)MDB7" || ver == "12.4(24)MDB8" || ver == "12.4(24)MDB9")
  fixed_ver = "12.4(24)MDB17";
#12.4MR
else if (ver == "12.4(2)MR" || ver == "12.4(2)MR1" || ver == "12.4(4)MR" || ver == "12.4(4)MR1" || ver == "12.4(6)MR" || ver == "12.4(6)MR1" || ver == "12.4(9)MR" || ver == "12.4(11)MR" || ver == "12.4(12)MR" || ver == "12.4(12)MR1" || ver == "12.4(12)MR2" || ver == "12.4(16)MR" || ver == "12.4(16)MR1" || ver == "12.4(16)MR2" || ver == "12.4(19)MR" || ver == "12.4(19)MR1" || ver == "12.4(19)MR2" || ver == "12.4(19)MR3" || ver == "12.4(20)MR" || ver == "12.4(20)MR2")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4MRA
else if (ver == "12.4(20)MRA" || ver == "12.4(20)MRA1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4MRB
else if (ver == "12.4(20)MRB" || ver == "12.4(20)MRB1")
  fixed_ver = "15.1(4)M8";
#12.4SW
else if (ver == "12.4(11)SW" || ver == "12.4(11)SW1" || ver == "12.4(11)SW2" || ver == "12.4(11)SW3" || ver == "12.4(15)SW" || ver == "12.4(15)SW1" || ver == "12.4(15)SW2" || ver == "12.4(15)SW3" || ver == "12.4(15)SW4" || ver == "12.4(15)SW5" || ver == "12.4(15)SW6" || ver == "12.4(15)SW7" || ver == "12.4(15)SW8" || ver == "12.4(15)SW8a" || ver == "12.4(15)SW9")
  fixed_ver = "15.1(4)M8";
#12.4T
else if (ver == "12.4(2)T" || ver == "12.4(2)T1" || ver == "12.4(2)T2" || ver == "12.4(2)T3" || ver == "12.4(2)T4" || ver == "12.4(2)T5" || ver == "12.4(2)T6" || ver == "12.4(4)T" || ver == "12.4(4)T1" || ver == "12.4(4)T2" || ver == "12.4(4)T3" || ver == "12.4(4)T4" || ver == "12.4(4)T5" || ver == "12.4(4)T6" || ver == "12.4(4)T7" || ver == "12.4(4)T8" || ver == "12.4(6)T" || ver == "12.4(6)T1" || ver == "12.4(6)T10" || ver == "12.4(6)T11" || ver == "12.4(6)T12" || ver == "12.4(6)T2" || ver == "12.4(6)T3" || ver == "12.4(6)T4" || ver == "12.4(6)T5" || ver == "12.4(6)T5a" || ver == "12.4(6)T5b" || ver == "12.4(6)T5c" || ver == "12.4(6)T5d" || ver == "12.4(6)T5e" || ver == "12.4(6)T5f" || ver == "12.4(6)T6" || ver == "12.4(6)T7" || ver == "12.4(6)T8" || ver == "12.4(6)T9" || ver == "12.4(9)T" || ver == "12.4(9)T0a" || ver == "12.4(9)T1" || ver == "12.4(9)T2" || ver == "12.4(9)T3" || ver == "12.4(9)T4" || ver == "12.4(9)T5" || ver == "12.4(9)T6" || ver == "12.4(9)T7" || ver == "12.4(11)T" || ver == "12.4(11)T1" || ver == "12.4(11)T2" || ver == "12.4(11)T3" || ver == "12.4(11)T4" || ver == "12.4(15)T" || ver == "12.4(15)T1" || ver == "12.4(15)T10" || ver == "12.4(15)T11" || ver == "12.4(15)T12" || ver == "12.4(15)T13" || ver == "12.4(15)T13b" || ver == "12.4(15)T14" || ver == "12.4(15)T15" || ver == "12.4(15)T16" || ver == "12.4(15)T17" || ver == "12.4(15)T2" || ver == "12.4(15)T3" || ver == "12.4(15)T4" || ver == "12.4(15)T5" || ver == "12.4(15)T6" || ver == "12.4(15)T6a" || ver == "12.4(15)T7" || ver == "12.4(15)T8" || ver == "12.4(15)T9" || ver == "12.4(20)T" || ver == "12.4(20)T1" || ver == "12.4(20)T2" || ver == "12.4(20)T3" || ver == "12.4(20)T4" || ver == "12.4(20)T5" || ver == "12.4(20)T5a" || ver == "12.4(20)T6" || ver == "12.4(22)T" || ver == "12.4(22)T1" || ver == "12.4(22)T2" || ver == "12.4(22)T3" || ver == "12.4(22)T4" || ver == "12.4(22)T5" || ver == "12.4(24)T" || ver == "12.4(24)T1" || ver == "12.4(24)T10" || ver == "12.4(24)T2" || ver == "12.4(24)T3" || ver == "12.4(24)T3c" || ver == "12.4(24)T3e" || ver == "12.4(24)T3f" || ver == "12.4(24)T31f" || ver == "12.4(24)T3g" || ver == "12.4(24)T32f" || ver == "12.4(24)T33f" || ver == "12.4(24)T34f" || ver == "12.4(24)T35c" || ver == "12.4(24)T35f" || ver == "12.4(24)T4" || ver == "12.4(24)T4a" || ver == "12.4(24)T4b" || ver == "12.4(24)T4c" || ver == "12.4(24)T4d" || ver == "12.4(24)T4e" || ver == "12.4(24)T4f" || ver == "12.4(24)T4g" || ver == "12.4(24)T4h" || ver == "12.4(24)T4i" || ver == "12.4(24)T4j" || ver == "12.4(24)T4k" || ver == "12.4(24)T4l" || ver == "12.4(24)T4m" || ver == "12.4(24)T4n" || ver == "12.4(24)T4o" || ver == "12.4(24)T5" || ver == "12.4(24)T6" || ver == "12.4(24)T7" || ver == "12.4(24)T8" || ver == "12.4(24)T9")
  fixed_ver = "15.1(4)M8";
#12.4XA
else if (ver == "12.4(2)XA" || ver == "12.4(2)XA1" || ver == "12.4(2)XA2")
  fixed_ver = "15.1(4)M8";
#12.4XB
else if (ver == "12.4(2)XB" || ver == "12.4(2)XB1" || ver == "12.4(2)XB10" || ver == "12.4(2)XB11" || ver == "12.4(2)XB12" || ver == "12.4(2)XB2" || ver == "12.4(2)XB3" || ver == "12.4(2)XB4" || ver == "12.4(2)XB5" || ver == "12.4(2)XB6" || ver == "12.4(2)XB7" || ver == "12.4(2)XB8" || ver == "12.4(2)XB9")
  fixed_ver = "15.1(4)M8";
#12.4XC
else if (ver == "12.4(4)XC" || ver == "12.4(4)XC1" || ver == "12.4(4)XC2" || ver == "12.4(4)XC3" || ver == "12.4(4)XC4" || ver == "12.4(4)XC5" || ver == "12.4(4)XC6" || ver == "12.4(4)XC7")
  fixed_ver = "15.1(4)M8";
#12.4XD
else if (ver == "12.4(4)XD" || ver == "12.4(4)XD1" || ver == "12.4(4)XD10" || ver == "12.4(4)XD11" || ver == "12.4(4)XD12" || ver == "12.4(4)XD2" || ver == "12.4(4)XD3" || ver == "12.4(4)XD4" || ver == "12.4(4)XD5" || ver == "12.4(4)XD6" || ver == "12.4(4)XD7" || ver == "12.4(4)XD8" || ver == "12.4(4)XD9")
  fixed_ver = "15.1(4)M8";
#12.4XE
else if (ver == "12.4(6)XE" || ver == "12.4(6)XE1" || ver == "12.4(6)XE2" || ver == "12.4(6)XE3")
  fixed_ver = "15.1(4)M8";
#12.4XF
else if (ver == "12.4(15)XF")
  fixed_ver = "15.1(4)M8";
#12.4XG
else if (ver == "12.4(9)XG" || ver == "12.4(9)XG1" || ver == "12.4(9)XG2" || ver == "12.4(9)XG3" || ver == "12.4(9)XG4" || ver == "12.4(9)XG5")
  fixed_ver = "15.1(4)M8";
#12.4XJ
else if (ver == "12.4(11)XJ" || ver == "12.4(11)XJ1" || ver == "12.4(11)XJ2" || ver == "12.4(11)XJ3" || ver == "12.4(11)XJ4" || ver == "12.4(11)XJ5" || ver == "12.4(11)XJ6")
  fixed_ver = "15.1(4)M8";
#12.4XK
else if (ver == "12.4(14)XK")
  fixed_ver = "15.1(4)M8";
#12.4XL
else if (ver == "12.4(15)XL" || ver == "12.4(15)XL1" || ver == "12.4(15)XL2" || ver == "12.4(15)XL3" || ver == "12.4(15)XL4" || ver == "12.4(15)XL5")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4XM
else if (ver == "12.4(15)XM" || ver == "12.4(15)XM1" || ver == "12.4(15)XM2" || ver == "12.4(15)XM3")
  fixed_ver = "15.1(4)M8";
#12.4XN
else if (ver == "12.4(15)XN")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4XP
else if (ver == "12.4(6)XP")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4XQ
else if (ver == "12.4(15)XQ" || ver == "12.4(15)XQ1" || ver == "12.4(15)XQ2" || ver == "12.4(15)XQ2a" || ver == "12.4(15)XQ2b" || ver == "12.4(15)XQ2c" || ver == "12.4(15)XQ2d" || ver == "12.4(15)XQ3" || ver == "12.4(15)XQ4" || ver == "12.4(15)XQ5" || ver == "12.4(15)XQ6" || ver == "12.4(15)XQ7" || ver == "12.4(15)XQ8")
  fixed_ver = "15.1(4)M8";
#12.4XR
else if (ver == "12.4(15)XR" || ver == "12.4(15)XR1" || ver == "12.4(15)XR10" || ver == "12.4(15)XR2" || ver == "12.4(15)XR3" || ver == "12.4(15)XR4" || ver == "12.4(15)XR5" || ver == "12.4(15)XR6" || ver == "12.4(15)XR7" || ver == "12.4(15)XR8" || ver == "12.4(15)XR9" || ver == "12.4(22)XR" || ver == "12.4(22)XR1" || ver == "12.4(22)XR10" || ver == "12.4(22)XR11" || ver == "12.4(22)XR12" || ver == "12.4(22)XR2" || ver == "12.4(22)XR3" || ver == "12.4(22)XR4" || ver == "12.4(22)XR5" || ver == "12.4(22)XR6" || ver == "12.4(22)XR7" || ver == "12.4(22)XR8" || ver == "12.4(22)XR9")
  fixed_ver = "15.1(4)M8";
#12.4XT
else if (ver == "12.4(6)XT" || ver == "12.4(6)XT1" || ver == "12.4(6)XT2")
  fixed_ver = "15.1(4)M8";
#12.4XV
else if (ver == "12.4(11)XV" || ver == "12.4(11)XV1")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4XW
else if (ver == "12.4(11)XW" || ver == "12.4(11)XW1" || ver == "12.4(11)XW10" || ver == "12.4(11)XW2" || ver == "12.4(11)XW3" || ver == "12.4(11)XW4" || ver == "12.4(11)XW5" || ver == "12.4(11)XW6" || ver == "12.4(11)XW7" || ver == "12.4(11)XW8" || ver == "12.4(11)XW9")
  fixed_ver = "15.1(4)M8";
#12.4XY
else if (ver == "12.4(15)XY" || ver == "12.4(15)XY1" || ver == "12.4(15)XY2" || ver == "12.4(15)XY3" || ver == "12.4(15)XY4" || ver == "12.4(15)XY5")
  fixed_ver = "15.1(4)M8";
#12.4XZ
else if (ver == "12.4(15)XZ" || ver == "12.4(15)XZ1" || ver == "12.4(15)XZ2")
  fixed_ver = "15.1(4)M8";
#12.4YA
else if (ver == "12.4(20)YA" || ver == "12.4(20)YA1" || ver == "12.4(20)YA2" || ver == "12.4(20)YA3")
  fixed_ver = "15.1(4)M8";
#12.4YB
else if (ver == "12.4(22)YB" || ver == "12.4(22)YB1" || ver == "12.4(22)YB2" || ver == "12.4(22)YB3" || ver == "12.4(22)YB4" || ver == "12.4(22)YB5" || ver == "12.4(22)YB6" || ver == "12.4(22)YB7" || ver == "12.4(22)YB8")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4YD
else if (ver == "12.4(22)YD" || ver == "12.4(22)YD1" || ver == "12.4(22)YD2" || ver == "12.4(22)YD3" || ver == "12.4(22)YD4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4YE
else if (ver == "12.4(22)YE" || ver == "12.4(22)YE1" || ver == "12.4(22)YE2" || ver == "12.4(22)YE3" || ver == "12.4(22)YE4" || ver == "12.4(22)YE5" || ver == "12.4(22)YE6" || ver == "12.4(24)YE" || ver == "12.4(24)YE1" || ver == "12.4(24)YE2" || ver == "12.4(24)YE3" || ver == "12.4(24)YE3a" || ver == "12.4(24)YE3b" || ver == "12.4(24)YE3c" || ver == "12.4(24)YE3d" || ver == "12.4(24)YE3e" || ver == "12.4(24)YE4" || ver == "12.4(24)YE5" || ver == "12.4(24)YE6" || ver == "12.4(24)YE7")
  fixed_ver = "15.1(4)M8";
#12.4YG
else if (ver == "12.4(24)YG1" || ver == "12.4(24)YG2" || ver == "12.4(24)YG3" || ver == "12.4(24)YG4")
  fixed_ver = "Refer to the vendor for a fix.";
#12.4YS
else if (ver == "12.4(24)YS" || ver == "12.4(24)YS1" || ver == "12.4(24)YS2" || ver == "12.4(24)YS3" || ver == "12.4(24)YS4" || ver == "12.4(24)YS5")
  fixed_ver = "Refer to the vendor for a fix.";
#15.0EJ
else if (ver == "15.0(2)EJ")
  fixed_ver = "15.0(2)EJ1";
#15.0EX
else if (ver == "15.0(2)EX" || ver == "15.0(2)EX1" || ver == "15.0(2)EX2" || ver == "15.0(2)EX3" || ver == "15.0(2)EX4")
  fixed_ver = "Refer to the vendor for a fix.";
#15.0EZ
else if (ver == "15.0(1)EZ" || ver == "15.0(1)EZ1" || ver == "15.0(2)EZ")
  fixed_ver = "15.0(1)EZ2";
#15.0M
else if (ver == "15.0(1)M" || ver == "15.0(1)M1" || ver == "15.0(1)M10" || ver == "15.0(1)M2" || ver == "15.0(1)M3" || ver == "15.0(1)M4" || ver == "15.0(1)M5" || ver == "15.0(1)M6" || ver == "15.0(1)M6a" || ver == "15.0(1)M7" || ver == "15.0(1)M8" || ver == "15.0(1)M9")
  fixed_ver = "15.1(4)M8";
#15.0MR
else if (ver == "15.0(1)MR" || ver == "15.0(2)MR")
  fixed_ver = "Refer to the vendor for a fix.";
#15.0S
else if (ver == "15.0(1)S" || ver == "15.0(1)S1" || ver == "15.0(1)S2" || ver == "15.0(1)S3a" || ver == "15.0(1)S4" || ver == "15.0(1)S4a" || ver == "15.0(1)S5" || ver == "15.0(1)S6")
  fixed_ver = "15.2(4)S5";
#15.0SE
else if (ver == "15.0(1)SE" || ver == "15.0(1)SE1" || ver == "15.0(1)SE2" || ver == "15.0(1)SE3" || ver == "15.0(2)SE" || ver == "15.0(2)SE1" || ver == "15.0(2)SE2" || ver == "15.0(2)SE3" || ver == "15.0(2)SE4" || ver == "15.0(2)SE5")
  fixed_ver = "15.0(2)SE6";
#15.0SY
else if (ver == "15.0(1)SY" || ver == "15.0(1)SY1" || ver == "15.0(1)SY2" || ver == "15.0(1)SY3" || ver == "15.0(1)SY4" || ver == "15.0(1)SY5")
  fixed_ver = "15.0(1)SY6";
#15.0XA
else if (ver == "15.0(1)XA" || ver == "15.0(1)XA1" || ver == "15.0(1)XA2" || ver == "15.0(1)XA3" || ver == "15.0(1)XA4" || ver == "15.0(1)XA5")
  fixed_ver = "15.1(4)M8";
#15.1EY
else if (ver == "15.1(2)EY" || ver == "15.1(2)EY1" || ver == "15.1(2)EY1a" || ver == "15.1(2)EY2" || ver == "15.1(2)EY2a" || ver == "15.1(2)EY3" || ver == "15.1(2)EY4")
  fixed_ver = "15.2(4)S5";
#15.1GC
else if (ver == "15.1(2)GC" || ver == "15.1(2)GC1" || ver == "15.1(2)GC2" || ver == "15.1(4)GC" || ver == "15.1(4)GC1" || ver == "15.1(4)GC2")
  fixed_ver = "15.1(4)M8";
#15.1M
else if (ver == "15.1(4)M" || ver == "15.1(4)M0a" || ver == "15.1(4)M0b" || ver == "15.1(4)M1" || ver == "15.1(4)M2" || ver == "15.1(4)M3" || ver == "15.1(4)M3a" || ver == "15.1(4)M4" || ver == "15.1(4)M5" || ver == "15.1(4)M6" || ver == "15.1(4)M7")
  fixed_ver = "15.1(4)M8";
#15.1MR
else if (ver == "15.1(1)MR" || ver == "15.1(1)MR1" || ver == "15.1(1)MR2" || ver == "15.1(1)MR3" || ver == "15.1(1)MR4" || ver == "15.1(1)MR5" || ver == "15.1(1)MR6" || ver == "15.1(3)MR")
  fixed_ver = "Refer to the vendor for a fix.";
#15.1MRA
else if (ver == "15.1(3)MRA" || ver == "15.1(3)MRA1" || ver == "15.1(3)MRA2")
  fixed_ver = "15.1(3)MRA3";
#15.1S
else if (ver == "15.1(1)S" || ver == "15.1(1)S1" || ver == "15.1(1)S2" || ver == "15.1(2)S" || ver == "15.1(2)S1" || ver == "15.1(2)S2" || ver == "15.1(3)S" || ver == "15.1(3)S0a" || ver == "15.1(3)S1" || ver == "15.1(3)S2" || ver == "15.1(3)S3" || ver == "15.1(3)S4" || ver == "15.1(3)S5" || ver == "15.1(3)S5a" || ver == "15.1(3)S6")
  fixed_ver = "15.2(4)S5";
#15.1SNG
else if (ver == "15.1(2)SNG")
  fixed_ver = "Refer to the vendor for a fix.";
#15.1SNH
else if (ver == "15.1(2)SNH" || ver == "15.1(2)SNH1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.1SNI
else if (ver == "15.1(2)SNI" || ver == "15.1(2)SNI1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.1SY
else if (ver == "15.1(1)SY" || ver == "15.1(1)SY1" || ver == "15.1(1)SY2" || ver == "15.1(2)SY" || ver == "15.1(2)SY1")
  fixed_ver = "15.1(2)SY2 / 15.1(1)SY3";
#15.1T
else if (ver == "15.1(1)T" || ver == "15.1(1)T1" || ver == "15.1(1)T2" || ver == "15.1(1)T3" || ver == "15.1(1)T4" || ver == "15.1(1)T5" || ver == "15.1(2)T" || ver == "15.1(2)T0a" || ver == "15.1(2)T1" || ver == "15.1(2)T2" || ver == "15.1(2)T2a" || ver == "15.1(2)T3" || ver == "15.1(2)T4" || ver == "15.1(2)T5" || ver == "15.1(3)T" || ver == "15.1(3)T1" || ver == "15.1(3)T2" || ver == "15.1(3)T3" || ver == "15.1(3)T4")
  fixed_ver = "15.1(4)M8";
#15.1XB
else if (ver == "15.1(1)XB" || ver == "15.1(1)XB1" || ver == "15.1(1)XB2" || ver == "15.1(1)XB3" || ver == "15.1(4)XB4" || ver == "15.1(4)XB5" || ver == "15.1(4)XB5a" || ver == "15.1(4)XB6" || ver == "15.1(4)XB7" || ver == "15.1(4)XB8" || ver == "15.1(4)XB8a")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2E
else if (ver == "15.2(1)E" || ver == "15.2(1)E1")
  fixed_ver = "15.2(1)E2";
#15.2EY
else if (ver == "15.2(1)EY")
  fixed_ver = "15.2(1)E2";
#15.2GC
else if (ver == "15.2(1)GC" || ver == "15.2(1)GC1" || ver == "15.2(1)GC2" || ver == "15.2(2)GC" || ver == "15.2(3)GC" || ver == "15.2(3)GC1" || ver == "15.2(4)GC")
  fixed_ver = "15.2(4)GC1";
#15.2GCA
else if (ver == "15.2(3)GCA" || ver == "15.2(3)GCA1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JA
else if (ver == "15.2(2)JA" || ver == "15.2(2)JA1" || ver == "15.2(4)JA" || ver == "15.2(4)JA1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JAX
else if (ver == "15.2(2)JAX" || ver == "15.2(2)JAX1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JB
else if (ver == "15.2(2)JB" || ver == "15.2(2)JB1" || ver == "15.2(2)JB2" || ver == "15.2(2)JB3" || ver == "15.2(4)JB" || ver == "15.2(4)JB1" || ver == "15.2(4)JB2" || ver == "15.2(4)JB3" || ver == "15.2(4)JB3a")
  fixed_ver = "15.2(4)JB3s / 15.2(4)JB4";
#15.2JN
else if (ver == "15.2(2)JN1" || ver == "15.2(2)JN2" || ver == "15.2(4)JN")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3" || ver == "15.2(4)M4" || ver == "15.2(4)M5")
  fixed_ver = "15.2(4)M6";
#15.2S
else if (ver == "15.2(1)S" || ver == "15.2(1)S1" || ver == "15.2(1)S2" || ver == "15.2(2)S" || ver == "15.2(2)S0a" || ver == "15.2(2)S0c" || ver == "15.2(2)S0d" || ver == "15.2(2)S1" || ver == "15.2(2)S2" || ver == "15.2(4)S" || ver == "15.2(4)S0c" || ver == "15.2(4)S1" || ver == "15.2(4)S2" || ver == "15.2(4)S3" || ver == "15.2(4)S3a" || ver == "15.2(4)S4" || ver == "15.2(4)S4a")
  fixed_ver = "15.2(4)S5";
#15.2SNG
else if (ver == "15.2(2)SNG")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2SNH
else if (ver == "15.2(2)SNH" || ver == "15.2(2)SNH1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2SNI
else if (ver == "15.2(2)SNI")
  fixed_ver = "15.4(1)S1 / 15.4(2)S";
#15.2T
else if (ver == "15.2(1)T" || ver == "15.2(1)T1" || ver == "15.2(1)T2" || ver == "15.2(1)T3" || ver == "15.2(1)T3a" || ver == "15.2(1)T4" || ver == "15.2(2)T" || ver == "15.2(2)T1" || ver == "15.2(2)T2" || ver == "15.2(2)T3" || ver == "15.2(2)T4" || ver == "15.2(3)T" || ver == "15.2(3)T1" || ver == "15.2(3)T2" || ver == "15.2(3)T3" || ver == "15.2(3)T4")
  fixed_ver = "15.2(4)M6";
#15.2XA
else if (ver == "15.2(3)XA")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "Refer to the vendor for a fix.";
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(1)S1e" || ver == "15.3(1)S2" || ver == "15.3(2)S" || ver == "15.3(2)S0a" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1" || ver == "15.3(2)S1b" || ver == "15.3(2)S1c" || ver == "15.3(2)S2" || ver == "15.3(3)S" || ver == "15.3(3)S0b" || ver == "15.3(3)S1" || ver == "15.3(3)S1a")
  fixed_ver = "15.3(3)S2";
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(2)T" || ver == "15.3(2)T1" || ver == "15.3(2)T2")
  fixed_ver = "15.3(2)T3";
#15.4S
else if (ver == "15.4(1)S" || ver == "15.4(1)S0a")
  fixed_ver = "15.4(1)S1 / 15.4(2)S";

if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"\s+ip\s+nat\s+[eio]", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
