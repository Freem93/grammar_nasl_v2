#TRUSTED 8f6206f24dd1e6e8879398742a5d0a324ce1e903989ab1f8090161940db2e8d9d3ca7af38dddce9a7b414698dfa2058c791c96e7f2139e9b5825b1b818f9e94cf0f9e033e3468add46a8899144a235eac295451d3ff8f6b97e2547ec6bd9b59029e38eb700d2ec53435b5b80ec85af8e42cc93ce2c186ada70480734b3950a932387c16a0b590e31da06c496b475bf4382956d1eb14816de5a9a314e2f899714069136e906bac65eddb5e6de762a9c10777abccf6251a0bceea4f08d791abba4bbe1f014db51796b04096ccc33385d427f192f64e6f39fc20b4f17a49c1644e21cb062b61fbf4de85dca3ab803292fb233c2cc6fe4534c532f8704468c372e95ab0166facc26f9538906a05177c6336d40d5949b6adbea748605d80519a0b27c9bc37a83267457c455429f535efd046a9a1e54d6c0a74be7a31bc8bb47eec299ed31ab278ee868cc9848c38f8d57365a64ad224f107b5c7ee30da5a3cc47d8256677749d199291a2f5c4b34f37926c4521cdbfd97b31eabc9e892ef92c2d835132a7efb6d73d4875c8384440e42c1e0090a357ecebf50300b0510e1e5c3c3d9a8af1e639fdde933a1776c886914c8c6afe2b4b001d93d8953864899ec98c9247451919ad5a5ec64c0fcc05c09c33c3feb2cb1bb3f1ddd8fc2b8872160175bf8f66594e504b96f629b7b518068ddead46875ffbe68f21cadbbf050ab484df0312
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76882);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6692");
  script_bugtraq_id(63855);
  script_osvdb_id(100112);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh04949");

  script_name(english:"Cisco IOS XE DHCP AAA Clients DoS (CSCuh04949)");
  script_summary(english:"Checks IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

A denial of service flaw exists in the DHCP function when handling AAA
client IP address assignment. An authenticated attacker, with a
specially crafted AAA packet, could cause the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31860");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6692
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8f0ba77");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuh04949.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

if (version == '3.7.0S') flag++;
if (version == '3.7.1S') flag++;
if (version == '3.7.2S') flag++;
if (version == '3.7.3S') flag++;
if (version == '3.8.0S') flag++;
if (version == '3.8.1S') flag++;
if (version == '3.8.2S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"aaa", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuh04949' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
