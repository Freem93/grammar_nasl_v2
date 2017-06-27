#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81514);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/26 14:38:27 $");

  script_bugtraq_id(65887);
  script_osvdb_id(
    103844,
    103845,
    103846,
    103847,
    103848
  );

  script_name(english:"X2Engine < 3.7.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of X2Engine.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the X2Engine application installed on
the remote web server is prior to version 3.7.4. It is, therefore,
potentially affected by multiple vulnerabilities :

  - Multiple SQL injection vulnerabilities exist in the
    'lastEventId' and 'lastTimestamp' HTTP GET parameters of
    the '/index.php/profile/getEvents' script.

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the 'Contacts[firstName]', 'Contacts[website]',
    'Contacts[company]', and 'Contacts[interest]' HTTP POST
    parameters of the '/index.php/contacts/create' script;
    and the 'Docs[name]' HTTP POST parameter of the
    '/index.php/docs/create' script.

  - An arbitrary file upload vulnerability exists due to the
    '/index.php/media/ajaxUpload' script not properly
    validating user-uploaded files.

  - A DOM-based cross-site scripting (XSS) vulnerability
    exists in the 'CKEditorFuncNum' HTTP POST parameter of
    the '/index.php/media/ajaxUpload' script.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://hauntit.blogspot.com/2014/02/en-multiple-vulnerabilities-in-x2engine.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ee9a12b");
  # http://x2community.com/topic/1511-multiple-vulnerabilities-in-x2engine/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?410174a0");
  script_set_attribute(attribute:"see_also", value:"http://x2community.com/topic/1517-x2engine-374/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/X2Engine/X2Engine/blob/master/CHANGELOG.md");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:x2engine:x2crm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("x2engine_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/X2Engine", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "X2Engine";
fix = "3.7.4";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir + "/login");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 7) ||
  (ver[0] == 3 && ver[1] == 7 && ver[2] < 4)
)
{
  set_kb_item(name:"www/" + port + "/XSS", value:TRUE);
  set_kb_item(name:'www/' + port + '/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
