#TRUSTED ad5adfc3dea7ef4e1b1b8878a82d9b241ec11b7bb6acd3001cdb4edc68453a3e67a8a566b4f22ccb0839feec4c79c33892c926223b04f677357d725d36e7b0fe6c9a39c1a87108119811b837bf258c534ba6824b0005b337ac5d6ef29aceac6a75dc305ebe7898fed0e9022b77cf2a4f6f8f16c0c63bc7d86d45344a8c214eaded0868b089489ca7dd5375e522c2a48758149413cfd9045eed0862b0804d562217d97635fe9d0514890c921236d54eec761927af7be0c1246000926338aad46f004e6ac481414da03b6c82f4302106d18067ad731bc9ad338caa1f8d845540d23d7e0c5e611b7de038935eb7e71a4ef9d237a9bc0c4f655eae82a109d74aeb5484543d00cf6516059fc34e9c6250d4336b775fe364e48dc3c8ba255911e8fc93d1b3d64beb0283dfead354ef3626bbdebe187882f5a91bb9111e7729c27e75d1b2d7f7f6b3fe6b4a4547c6b055e8bf129e83d22d8831a33672ddc9c1ee9336636a7edac1aed759c4f9a0712c26a1e6145658178df1e6d641d2eb89e576e1cac88bc09c1995ae71574f172493369e2278f512b8d736c87cc8008900e692b8374f3cd76c2e2cfc572345fcdfe62fc96c6e0d8673755cf50bc4985597133c015bf5b43526a6e03e41342502cbcf131d62f687cef812563b1b102821c2c3cefe30f117f3a6167f68638b4dd10c7e1574b7724271688470c7920502a35dc71f103e21
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78037);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3360");
  script_bugtraq_id(70141);
  script_osvdb_id(112043);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul46586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-sip");

  script_name(english:"Cisco IOS Software SIP DoS (cisco-sa-20140924-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a vulnerability in the
Session Initiation Protocol (SIP) implementation due to improper
handling of SIP messages. A remote attacker can exploit this issue by
sending specially crafted SIP messages to cause the device to reload.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS versions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61c56b95");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35611");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35259");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul46586");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCul46586";
fixed_ver = NULL;

#12.4GC
if (ver == "12.4(22)GC1" || ver == "12.4(22)GC1a" || ver == "12.4(24)GC1" || ver == "12.4(24)GC3" || ver == "12.4(24)GC3a" || ver == "12.4(24)GC4" || ver == "12.4(24)GC5")
  fixed_ver = "Refer to the vendor.";
#12.4T
else if (ver == "12.4(22)T" || ver == "12.4(22)T1" || ver == "12.4(22)T2" || ver == "12.4(22)T3" || ver == "12.4(22)T4" || ver == "12.4(22)T5" || ver == "12.4(24)T" || ver == "12.4(24)T1" || ver == "12.4(24)T10" || ver == "12.4(24)T11" || ver == "12.4(24)T2" || ver == "12.4(24)T3" || ver == "12.4(24)T4" || ver == "12.4(24)T5" || ver == "12.4(24)T6" || ver == "12.4(24)T7" || ver == "12.4(24)T8" || ver == "12.4(24)T9")
  fixed_ver = "12.4(24)T3a, 12.4(24)T4a, or 12.4(24)T12";
#12.4YA
else if (ver == "12.4(20)YA" || ver == "12.4(20)YA1" || ver == "12.4(20)YA2" || ver == "12.4(20)YA3")
  fixed_ver = "12.4(24)T3a, 12.4(24)T4a, or 12.4(24)T12";
#12.4YB
else if (ver == "12.4(22)YB" || ver == "12.4(22)YB1" || ver == "12.4(22)YB2" || ver == "12.4(22)YB3" || ver == "12.4(22)YB4" || ver == "12.4(22)YB5" || ver == "12.4(22)YB6" || ver == "12.4(22)YB7" || ver == "12.4(22)YB8")
  fixed_ver = "Refer to the vendor.";
#15.0M
else if (ver == "15.0(1)M" || ver == "15.0(1)M1" || ver == "15.0(1)M10" || ver == "15.0(1)M2" || ver == "15.0(1)M3" || ver == "15.0(1)M4" || ver == "15.0(1)M5" || ver == "15.0(1)M6" || ver == "15.0(1)M7" || ver == "15.0(1)M8" || ver == "15.0(1)M9")
  fixed_ver = "15.0(1)M6a";
#15.0XA
else if (ver == "15.0(1)XA" || ver == "15.0(1)XA1" || ver == "15.0(1)XA2" || ver == "15.0(1)XA3" || ver == "15.0(1)XA4" || ver == "15.0(1)XA5")
  fixed_ver = "15.1(4)M9";
#15.1GC
else if (ver == "15.1(2)GC" || ver == "15.1(2)GC1" || ver == "15.1(2)GC2" || ver == "15.1(4)GC" || ver == "15.1(4)GC1")
  fixed_ver = "15.1(4)GC2";
#15.1M
else if (ver == "15.1(4)M" || ver == "15.1(4)M0a" || ver == "15.1(4)M0b" || ver == "15.1(4)M1" || ver == "15.1(4)M2" || ver == "15.1(4)M3" || ver == "15.1(4)M3a" || ver == "15.1(4)M4" || ver == "15.1(4)M5" || ver == "15.1(4)M6" || ver == "15.1(4)M7" || ver == "15.1(4)M8")
  fixed_ver = "15.1(4)M9";
#15.1T
else if (ver == "15.1(1)T" || ver == "15.1(1)T1" || ver == "15.1(1)T2" || ver == "15.1(1)T3" || ver == "15.1(1)T4" || ver == "15.1(1)T5" || ver == "15.1(2)T" || ver == "15.1(2)T0a" || ver == "15.1(2)T1" || ver == "15.1(2)T2" || ver == "15.1(2)T2a" || ver == "15.1(2)T3" || ver == "15.1(2)T4" || ver == "15.1(2)T5" || ver == "15.1(3)T" || ver == "15.1(3)T1" || ver == "15.1(3)T2" || ver == "15.1(3)T3" || ver == "15.1(3)T4")
  fixed_ver = "15.1(4)M9";
#15.1XB
else if (ver == "15.1(1)XB" || ver == "15.1(1)XB1" || ver == "15.1(1)XB2" || ver == "15.1(1)XB3" || ver == "15.1(4)XB4" || ver == "15.1(4)XB5" || ver == "15.1(4)XB5a" || ver == "15.1(4)XB6" || ver == "15.1(4)XB7" || ver == "15.1(4)XB8" || ver == "15.1(4)XB8a")
  fixed_ver = "15.1(4)M9";
#15.2GC
else if (ver == "15.2(1)GC" || ver == "15.2(1)GC1" || ver == "15.2(1)GC2" || ver == "15.2(2)GC" || ver == "15.2(3)GC" || ver == "15.2(3)GC1" || ver == "15.2(4)GC" || ver == "15.2(4)GC1" || ver == "15.2(4)GC2")
  fixed_ver = "15.2(4)M7";
#15.2GCA
else if (ver == "15.2(3)GCA" || ver == "15.2(3)GCA1")
  fixed_ver = "15.4(1)T2 or 15.4(2)T";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3" || ver == "15.2(4)M4" || ver == "15.2(4)M5" || ver == "15.2(4)M6" || ver == "15.2(4)M6b")
  fixed_ver = "15.2(4)M7";
#15.2T
else if (ver == "15.2(1)T" || ver == "15.2(1)T1" || ver == "15.2(1)T2" || ver == "15.2(1)T3" || ver == "15.2(1)T3a" || ver == "15.2(1)T4" || ver == "15.2(2)T" || ver == "15.2(2)T1" || ver == "15.2(2)T2" || ver == "15.2(2)T3" || ver == "15.2(2)T4" || ver == "15.2(3)T" || ver == "15.2(3)T1" || ver == "15.2(3)T2" || ver == "15.2(3)T3" || ver == "15.2(3)T4")
  fixed_ver = "15.2(4)M7";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "15.2(4)XB11";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1" || ver == "15.3(3)M2" || ver == "15.3(3)M3")
  fixed_ver = "15.3(3)M4";
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(1)T4" || ver == "15.3(2)T" || ver == "15.3(2)T1" || ver == "15.3(2)T2" || ver == "15.3(2)T3")
  fixed_ver = "15.3(2)T4";
#15.4CG
else if (ver == "15.4(1)CG")
  fixed_ver = "15.4(1)CG1 or 15.4(2)CG";
#15.4T
else if (ver == "15.4(1)T" || ver == "15.4(1)T1")
  fixed_ver = "15.4(1)T2 or 15.4(2)T";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

# SIP check
# nb SIP can listen on TCP or UDP
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # SIP UDP listening check
  # Example:
  # 17     0.0.0.0             0 --any--          5060   0   0    11   0
  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:\S+\s+){4}5060\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # SIP TCP listening check
    # Example:
    # 7F1277405E20  0.0.0.0.5061               *.*                         LISTEN
    # 7F127BBE20D8  0.0.0.0.5060               *.*                         LISTEN
    buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^\S+\s+\S+(506[01])\s+", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because SIP is not listening on TCP or UDP.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
