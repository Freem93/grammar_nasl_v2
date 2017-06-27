#TRUSTED ad1320a344326a8e06f20330553c35f13b2ce91f700c3ab1aa698da52483b7a801683a16cfba4941343847b4f1096ff27bc102549dffe431bacbcccbe75c2d59021d3f71ed9cf7351677bb254b2a6cccd1d28bbc23a245590342d67856e822e90152d20ac4907db4b3441a22e7b6dd39a3160446cc96688fde50c414aa3be974bcfcc4d5fa65d43b0f6ffbc135e70317517ddfa6644a504f4210033a7d0121fff0cc0f934ff86231903cc24d3ae8fa942b0f04310fee845e353bc0ed256fb34d8357affa3eb540ec71312c104190203f4e793b45e206335eafcbf9e81ad3e10afa1feed6d12129b0fdcc667e48190cdcb8d9193d19d4d2173227bc6dac50f9fa989c072f0ea77f118a4bcda6957be7da5f4948a0e8b79c62846f8c4474f2ba9075b449a67ab5fe5485bcbd31a7eb2a2d5be58db959362b95409596d7631926c3a59f0e1ebd28ad3e8b26071c392b9c98fc4099a18e2ff52958da7693d899c8142e830f3e88fcfb93178f96f61cd155a52df156cad0f30636164a6cf2a57b837f47f96ce1f7be6674f7c58f39cdde11592d7ae1dc2292ed511489a5d6b2704f55d911aac173164fa307476493f5ff355d305385244c18f9634a66b21b4598f03cf9cd2e6c95b28e4e0f8c815306241158eb964c825ca0c60e3d8863570f33877d3c8687e4cac00426148026cbec89edf6b57488f56e9fb670c2bd8f48c35f83bf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76970);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3299");
  script_bugtraq_id(68177);
  script_osvdb_id(108377);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui79745");

  script_name(english:"Cisco IOS IPSec Packet DoS (CSCui79745)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS version.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

A denial of service flaw exists within IPSec packet handling. An
authenticated attacker, using a malformed IPSec packet, could cause
the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34704");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?961f4076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCui79745.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");

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

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;

if (version == '15.4(0.12)T') flag++;
if (version == '15.4(1)T') flag++;
if (version == '15.4(1)T1') flag++;
if (version == '15.4(1)T2') flag++;
if (version == '15.4(1)T3') flag++;
if (version == '15.4(2)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"crypto ipsec", string:buf)) flag = 1;
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCui79745' +
      '\n  Installed release : ' + version + 
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
