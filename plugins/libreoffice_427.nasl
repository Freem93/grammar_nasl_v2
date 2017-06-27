#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80079);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2014-3693");
  script_bugtraq_id(71351);
  script_osvdb_id(114326);

  script_name(english:"LibreOffice 4.x < 4.2.7 Impress Remote RCE");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a
use-after-free memory vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice is installed on the remote Windows host that
is 4.x prior to 4.2.7. It is, therefore, affected by a use-after-free
vulnerability related to the Impress Remote socket manager that allows
denial of service attacks or arbitrary code execution by means of a
specially crafted TCP request that causes already freed memory to be
dereferenced.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 4.2.7 (4.2.7.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2014-3693/");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "LibreOffice";

if (report_paranoia < 2) audit(AUDIT_PARANOID);

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version    = install['version'];
version_ui = install['display_version'];
path       = install['path'];

if (
  # 4.0.x / 4.1.x
  version =~ "^4\.[01]($|[^0-9])" ||
  # 4.2.x < 4.2.7
  version =~ "^4\.2\.[0-6]($|[^0-9])" ||
  # 4.2.7 Release is 4.2.7.2
  version =~ "^4\.2\.7\.[01]($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.2.7 (4.2.7.2)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui, path);
