#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71522);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id(
    "CVE-2013-7003",
    "CVE-2013-7032",
    "CVE-2013-7033",
    "CVE-2013-7034"
  );
  script_bugtraq_id(64202, 64376, 64378, 64383);
  script_osvdb_id(100828, 101080, 101119, 101120);

  script_name(english:"LiveZilla < 5.1.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of LiveZilla.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of LiveZilla hosted on the remote web server is affected
by multiple vulnerabilities :

  - The application is affected by multiple cross-site
    scripting (XSS) vulnerabilities because it fails to
    properly sanitize user-supplied input. Note that
    CVE-2013-7003 was reportedly fixed in version 5.1.2.0.
    (CVE-2013-7003, CVE-2013-7032)

  - The application insecurely stores credentials that are
    accessible via JavaScript. An attacker can gain access
    to these credentials by exploiting a cross-site
    scripting vulnerability. Note that the vendor update
    partially fixes the issue by storing the credentials
    as MD5 hashes. (CVE-2013-7033)

  - The application is affected by a PHP object injection
    vulnerability because it fails to properly sanitize
    user-supplied input to the 'setCookieValue()' function
    of the '_lib/functions.global.inc.php' script.
    (CVE-2013-7034)");
  # http://zoczus.blogspot.com/2013/12/en-livezilla-multiple-vulnerabilities.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86f60d46");
  script_set_attribute(attribute:"see_also", value:"http://www.livezilla.net/board/index.php?/topic/163-livezilla-changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to LiveZilla version 5.1.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:livezilla:livezilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("livezilla_detect.nbin");
  script_require_keys("installed_sw/LiveZilla", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

appname = "LiveZilla";

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
path    = install["path"];
version = install["version"];
install_url = build_url(port:port, qs:path);

fix = '5.1.2.1';

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 5 ||
  (ver[0] == 5 && ver[1] < 1) ||
  (ver[0] == 5 && ver[1] == 1 && ver[2] < 2) ||
  (ver[0] == 5 && ver[1] == 1 && ver[2] == 2 && ver[3] < 1)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
