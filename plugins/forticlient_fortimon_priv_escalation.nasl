#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31347);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_cve_id("CVE-2008-0779");
  script_bugtraq_id(27776);
  script_osvdb_id(42603);
  script_xref(name:"Secunia", value:"28975");

  script_name(english:"Fortinet FortiClient Host Security fortimon.sys Crafted Request Local Privilege Escalation");
  script_summary(english:"Checks the version of FortiClient.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a device driver that is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"FortiClient is installed on the remote host, providing it with a range
of security-related functionality.

The version of the fortimon.sys device driver installed on the remote
host as part of FortiClient allows a local user to escalate his
privileges by issuing a special request to the driver's device.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00934d7b");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/488071/100/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 3.0 MR5 Patch 4 (build 474) / 3.0 MR6
(build 534) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("installed_sw/FortiClient");

app = "FortiClient";

installs = get_installs(app_name:app);
if (installs[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, app);

install = installs[1][0];
path = install['path'];
version = install['version'];

fixed_version = "3.0.474.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
