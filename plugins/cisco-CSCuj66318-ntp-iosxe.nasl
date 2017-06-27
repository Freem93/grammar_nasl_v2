#TRUSTED 7be4ed228a86ab05949aa027e11167b266c0c1045fff8a98622c5dcad49a9b3a3ca250d13e97a75ae3b30607b7e0409eceb8cf44b5a70db9a084479d7768611a2bddcf0511a2e12063f1e0099f8644389cc2c5eea70fe15ad274e2f3642100f57ddbbb23bdfcad83a103d7e0da021300727f0085326dc64aa59b676c92fc2ef715fd3c718b3fdc1f3817e7997db14d42f3417d4ac0e80a2c599a1479b82012e3efdd8b40f63a94e0c02ba0a8703291892d99c9550cf38a86858f46f56490c92829cc1f86ae0a261bad1758e84573b3c5bc2eb28d3038b6215c5a29b6aea6694c1215d90f25f5ef9c9e3abce478024dd475747702813e441ba9421d8c3d08d2aa66c89ed1d205f22bc20be7afb4d8503c5afbf2650179eafc3feb6a418eac85378bc4fa4263ab8ec142f8bbf38015729dd89a5902f66333968118b91632ed6bbe4e0543172a009874de59f6584ae0ac0bb4e77a26f4ea18ad6baa528851b64b1f77621ed9126ef9f4ec92f07e2ab9c38f62a428922c4e9c9c51526b9dc42f4c006e8a8777ffcb0eb7734f05fb9e35538ae10b9e9a9124e0c2541b713071c430a9cb75f9d49a3fafc033e33184a9de859db6390ae70becbdb4e55bb84c7a4b542be94ebe70d767db1cc8791670d3eee9437e6e3dbcd3d191c3e225b1906f3cdfdfd41a0e2f85350e4051f98120dcafa6ac7d8c6d7b0a9bfee2db3a154113cbcad7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77053);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3309");
  script_bugtraq_id(68463);
  script_osvdb_id(108862);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj66318");

  script_name(english:"Cisco IOS XE NTP Information Disclosure (CSCuj66318)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device potentially contains an issue with the 'ntp
access-group' which could allow a remote attacker to bypass the NTP
access group and query an NTP server configured to deny-all requests.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3309
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?854f9178");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj66318.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

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
# Per the advisory, IOS XE affected:
# 3.5S Base, .0, .1, .2
# 3.6S Base, .0, .1, .2
# 3.8S Base, .0, .1, .2
# 3.7S Base, .0, .1, .2, .3, .4
# 3.9S .0, .1
# 3.10S .0, .0a, .1, .2
# 3.11S .1, .2
# No specific hardware conditions
# No workarounds
flag = 0;
if (
  version =~ "^3\.(5|6|8)\.[0-2]S?$" ||
  version =~ "^3\.7\.[0-4]S$"        ||
  version =~ "^3\.9\.[0-1]S?$"       ||
  version =~ "^3\.10\.(0|0a|1|2)S$"  ||
  version =~ "^3\.11\.[1-2]S$"
) flag++;

override = 0;
if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  # Check if NTP actually enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "ntp master" >< buf           ||
      "ntp peer" >< buf             ||
      "ntp broadcast client" >< buf ||
      "ntp multicast client" >< buf
    ) flag++;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuj66318' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
