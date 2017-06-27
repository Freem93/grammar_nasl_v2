#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70121);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2009-1943", "CVE-2009-3861");
  script_bugtraq_id(35154, 36907);
  script_osvdb_id(54831, 59660);

  script_name(english:"Juniper NetScreen VPN Client Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of Juniper NetScreen VPN Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by multiple buffer overflow
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Juniper NetScreen VPN client
that is affected by multiple buffer overflow vulnerabilities :

  - The IKE VPN service listening on UDP port 62514 is
    vulnerable to a stack overflow vulnerability that can be
    triggered by sending specially crafted packets.
    (CVE-2009-1943)

  - spdedit.exe has a flaw in parsing specially crafted SPD
    files that can be utilized to trigger a stack overflow.
    (CVE-2009-3861)

Successful exploitation of either of these vulnerabilities could allow a
remote attacker to execute arbitrary code on the host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-024/");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln36907.html");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln35154.html");
  script_set_attribute(attribute:"see_also", value:"http://www.senseofsecurity.com.au/advisories/SOS-09-008");
  script_set_attribute(attribute:"solution", value:"Upgrade to Juniper NetScreen 9.0r5 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SafeNet SoftRemote GROUPNAME Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen_remote_vpn_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("juniper_netscreen_installed.nasl");
  script_require_keys("SMB/Juniper NetScreen/Path", "SMB/Juniper NetScreen/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/Juniper NetScreen/Version');
path    = get_kb_item_or_exit('SMB/Juniper NetScreen/Path');

# fix : 9.0r5 / 10.8.10 (Build 4)
item = eregmatch(string:version, pattern:"([0-9.]+) \(Build ([0-9]+)\)");
if (isnull(item)) exit(1, 'Failed to parse the version string.');

build = int(item[2]);

if (
  ver_compare(ver:item[1], fix:'10.8.10', strict:FALSE) == -1 ||
  (item[1] == "10.8.10" && build < 4)
)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.8.10 (Build 4) / 9.0r5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'Juniper NetScreen', version, path);
