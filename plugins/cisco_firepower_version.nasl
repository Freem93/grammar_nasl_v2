#TRUSTED 5426169d320412922677afe20e11528ec07689b6fa22864594acd30ea124bbc5c3662d0f38858d73cfa32f9c514760064e22661d69560286abd04b9c0ae0a60adde4194c158e1aefa32bb2f4be88ba4fc744b9fe36a569da7bb712977f97422aca6a2dade09b35437eac052e3d227d5e91e1585fd62f920147b903bd952145bf9e0bd88404e76a4f0fcfd5efb57be9d273aade1b51fc203353b749a1dc64494834ca34ca35b9ab2cce24cd97f83e313b26c76d947ff28070f6cacdb20360f92b8a75a0f3fffad34ec339a27dbbb40fa441662b8fd79dda4643fc12a0994566c2575919c5941ea97c87a97876fa524c19a611ba7705f069018c743fd08b54b8c369ce745f1128a1c30c07b69248cfe345d17eb6161619b4b8069ff30d3058033cb54ad5bc3db90bea1cfd6aa166c42187d61f822046edff83264d8e9f64ead6dfa560a0d0d7741a8935c6c2760014bb10d87688a02f57b7cac96130826498b7a22b5c35401191db0f49d80973bd2b90eda11723ecaeb15a75410c510cc5ae5931b649c3a67f9f74998124e2b4f7aad9c7c45c5f158869849f9f845fcde59f42ac784a73a79b667c833d08112ae99e1e9c52f4688345a17c4986afe88426c966b9373c6000f2b3bf9f41c9bd7a876cbb91da2b3e013a66f24a6a67360e163ce65fe8d6a0759ceb8353c7176ca48ae32c9d932d200b1768cc1e68ec4595ad1bd304
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94470);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/02");

  script_name(english:"Cisco Firepower System Detection");
  script_summary(english:"Obtain the version of the remote Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"Cisco Firepower System is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Cisco Firepower System is running on the remote host. Firepower System
is a comprehensive management platform for managing firewalls,
application control, intrusion prevention, URL filtering, and advanced
malware protection.

It was possible to obtain version information for the Firepower System
using SSH.");
  #http://www.cisco.com/c/en/us/products/security/firesight-management-center/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93185175");
  #http://www.cisco.com/c/en/us/td/docs/security/firepower/roadmap/firepower-roadmap.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4742894b");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");

function report_and_exit(ver, model, source)
{
  local_var report;

  replace_kb_item(name:"Host/Cisco/firepower/Version", value:ver);
  replace_kb_item(name:"Host/Cisco/firepower", value:TRUE);

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + ver;
  report += '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

  exit(0);
}

uname = get_kb_item_or_exit("Host/uname");
if ( "Linux firepower" >!< uname ) audit(AUDIT_OS_NOT, "Cisco Firepower");

sock_g = ssh_open_connection();
if (! sock_g)
  audit(AUDIT_FN_FAIL, "ssh_open_connection");

firepower_ssh = ssh_cmd(cmd:"cat /etc/os.conf");
ssh_close_connection();

if (
  "OSVERSION" >< firepower_ssh &&
  "OSBUILD" >< firepower_ssh
)
{
  version = eregmatch(string:firepower_ssh, pattern:"OSVERSION=([0-9][0-9.]+)\s*([\r\n]|$)");

  if (!isnull(version))
  {
    version = version[1];
    build = eregmatch(string:firepower_ssh, pattern:"OSBUILD=([0-9]+)\s*([\r\n]|$)");
    if(!isnull(build))
      version += "-" + build[1];
    report_and_exit(ver:version, source:'SSH');
  }
}
audit(AUDIT_UNKNOWN_DEVICE_VER, "Cisco Firepower");
