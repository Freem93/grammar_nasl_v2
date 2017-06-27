#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26027);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/04 18:02:23 $");

  script_cve_id("CVE-2007-4909");
  script_bugtraq_id(25655);
  script_osvdb_id(40519);

  script_name(english:"WinSCP URL Protocol Handler Arbitrary File Transfer");
  script_summary(english:"Checks version of the WinSCP exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that allows arbitrary file
access.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of WinSCP on the remote
host fails to completely sanitize input to the SCP and SFTP protocol
handlers. If an attacker can trick a user on the affected host into
clicking on a malicious link, a file transfer can be initiated to or
from the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/479298/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://winscp.net/eng/docs/history#4.0.4");
  script_set_attribute(attribute:"solution", value:"Upgrade to WinSCP version 4.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winscp:winscp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("winscp_installed.nbin");
  script_require_keys("installed_sw/WinSCP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'WinSCP';
fixed_version = '4.0.4.346';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
