#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34029);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2008-3700", "CVE-2008-3701");
  script_bugtraq_id(30642);
  script_osvdb_id(47613, 47614, 47615, 47616);

  script_name(english:"Kayako SupportSuite < 3.30.01 Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by several
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Kayako SupportSuite, a web-based electronic
support portal written in PHP. 

According to its banner, the version of Kayako installed on the remote
host is earlier than 3.30.01 and is, therefore, affected by several 
issues:

  - There is a blind SQL injection issue in the staff panel
    that enables a staff user to gain administrative access.

  - A user may be able to inject arbitrary script code into 
    a user's browser by opening a ticket or requesting a 
    chat if they include the script in the 'Full Name' 
    field associated with their account.

  - There are numerous cross-site scripting issues.");

   # http://web.archive.org/web/20100225032305/http://www.gulftech.org/?node=research&article_id=00123-08092008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc3d0a16");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Aug/110");
   # http://web.archive.org/web/20080822232046/http://forums.kayako.com/f3/3-30-01-stable-released-18304/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eea1320");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kayako SupportSuite 3.30.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kayako:supportsuite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("kayako_supportsuite_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/kayako_supportsuite", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php: TRUE);
install = get_install_from_kb(appname:"kayako_supportsuite", port:port, exit_on_fail:TRUE);

dir         = install['dir'];
install_url = build_url(port:port,qs:dir);
version     = install['ver'];

if (version == UNKNOWN_VER || isnull(version))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "Kayako SupportSuite", install_url);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
# nb: make sure we have at least three components since we're 
#     testing for 3 (might not be needed).
while (i < 3)
  ver[i++] = 0;

fixed_version = '3.30.01';

if (
  ver[0] < 3 ||
  (
    ver[0] == 3 &&
    (
      ver[1] < 30 ||
      (ver[1] == 30 && ver[2] < 1)
    )
  )
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Kayako SupportSuite", install_url, version);
