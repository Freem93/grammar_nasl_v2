#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(64560);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2013-0197", "CVE-2013-1810", "CVE-2013-1811");
  script_bugtraq_id(57456, 57468, 57470);
  script_osvdb_id(89345, 89950, 95072);

  script_name(english:"MantisBT 1.2.x < 1.2.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MantisBT");

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

  - Version 1.2.12 of the application is affected by a
    cross-site scripting (XSS) vulnerability because the
    'search.php' script fails to properly sanitize
    user-supplied input to the 'match_type' parameter.  An
    attacker may be able to leverage this to inject
    arbitrary HTML and script code into a user's browser to
    be executed within the security context of the affected
    site. (CVE-2013-0197)

  - Version 1.2.12 of the application is affected by a
    cross-site scripting (XSS) vulnerability because the
    application fails to properly sanitize user-supplied
    input.  A user with manager or administrator privileges
    can create a category or project name containing
    JavaScript code.  This code would then be executed
    within the browser of a user visiting the summary.php
    script.

  - The application is affected by a workflow-related flaw
    as a user with 'Reporter' permissions can modify the
    status of any issue to 'New' even if the user does
    not have sufficient privileges to make the change.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  # http://hauntit.blogspot.de/2013/01/en-mantis-bug-tracker-1212-persistent.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26660ed2");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/changelog_page.php?version_id=180");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
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

# Versions 1.2.x less than 1.2.13 are vulnerable
if (ver[0] == 1 && ver[1] == 2 && ver[2] < 13)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.2.13\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
