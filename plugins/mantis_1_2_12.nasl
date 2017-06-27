#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(64561);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2012-5522", "CVE-2012-5523");
  script_bugtraq_id(56520);
  script_osvdb_id(87402, 87529);

  script_name(english:"MantisBT < 1.2.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mantis");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the MantisBT install hosted on the
remote web server is affected by multiple vulnerabilities :

  - The application is affected by an information
    disclosure vulnerability due to a flaw in using default
    values to determine if a user has sufficient privileges
    to modify the status of a bug.  This could allow an
    unauthenticated, remote attacker to modify the status
    of a bug. (CVE-2012-5522)

  - The application is affected by an information
    disclosure vulnerability because permissions are
    maintained when cloning and transferring an issue to
    another project.  This could allow a remote attacker
    to view the notes of a cloned issue provided they had
    sufficient privileges to view the notes of the original
    issue. (CVE-2012-5523)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/changelog_page.php?version_id=150");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 1.2.12 are vulnerable
if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] < 2) ||
  (ver[0] == 1 && ver[1] == 2 && ver[2] < 12)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.2.12\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
