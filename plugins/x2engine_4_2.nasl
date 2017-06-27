#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81438);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/24 14:39:21 $");

  script_cve_id("CVE-2014-5297", "CVE-2014-5298");
  script_bugtraq_id(70080, 70081);
  script_osvdb_id(111950, 111972);

  script_name(english:"X2Engine < 4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of X2Engine.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the X2Engine application installed on
the remote web server is potentially affected by multiple
vulnerabilities :

  - A PHP object injection vulnerability exists which can be
    used to carry out Server-Side Request Forgery (SSRF)
    attacks using specially crafted serialized objects. An
    attacker can exploit this issue by sending a crafted
    serialized request via the 'report' HTTP POST parameter
    of the 'SiteController.php' script. (CVE-2014-5297)

  - A file upload vulnerability exists in the script
    'FileUploadsFilter.php' due to a case-sensitive file
    name check by the regex contained in the constant
    'FileUploadsFilter::EXT_BLACKLIST'. An attacker, using a
    crafted file name with capital letters in the extension,
    can bypass file upload restrictions to load and execute
    arbitrary PHP scripts, provided the X2Engine is running
    under a case-insensitive file system or configuration.
    (CVE-2014-5298)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Sep/77");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Sep/78");
  script_set_attribute(attribute:"see_also", value:"http://x2community.com/topic/1804-important-security-patch/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/X2Engine/X2Engine/blob/master/CHANGELOG.md");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:x2engine:x2engine");
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
fix = "4.2";
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
  (ver[0] < 4) ||
  (ver[0] == 4 && ver[1] < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
