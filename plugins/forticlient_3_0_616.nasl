#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56049);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2009-1262");
  script_bugtraq_id(34343);
  script_osvdb_id(53266);

  script_name(english:"Fortinet FortiClient Crafted VPN Connection Name Handling Local Format String");
  script_summary(english:"Checks the version of FortiClient.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a security application that is
affected by a local format string vulnerability.");
  script_set_attribute(attribute:"description", value:
"FortiClient, a client-based software solution intended to provide
security features for enterprise computers and mobile devices, is
installed on the remote Windows host.

The installed version does not properly handle format string
specifiers within a VPN connection name. A local user may be able to
leverage this issue to read and write arbitrary memory with SYSTEM
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/502354/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 3.0 MR7 Patch 6 (3.0.616) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

fixed_version = "3.0.616";
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
