#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66392);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2013-1883", "CVE-2013-1930", "CVE-2013-1931");
  script_bugtraq_id(58626, 58889, 58890);
  script_osvdb_id(91618, 92024, 92025);

  script_name(english:"MantisBT 1.2.12 - 1.2.14 Multiple Vulnerabilities");
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
remote web server is affected by multiple vulnerabilities:

  - A flaw exists in the 'filter_api.php' script when
    conducting a search query on the View Issues page.
    Combining filter criteria could lead to a denial
    of service. (CVE-2013-1883)

  - A flaw exists that is due to the close button being
    displayed even when disallowed.  This may allow a
    remote attacker to change the ticket status without
    sufficient privileges. (CVE-2013-1930)

  - A cross-site scripting vulnerability exists in the
    'manage_proj_ver_delete.php' because the 'version'
    parameter does not properly sanitize input.  This
    flaw reportedly affects Mantis 1.2.14.
    (CVE-2013-1931)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/blog/?p=249");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=15453");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=15511");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=15573");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/13");

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

# Versions 1.2.12 - 1.2.14 are vulnerable
if (ver[0] == 1 && ver[1] == 2 && (ver[2] >= 12 && ver[2] < 15))
{
  if (ver[0] == 1 && ver[1] == 2 && ver[2] == 14)
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.2.15\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
