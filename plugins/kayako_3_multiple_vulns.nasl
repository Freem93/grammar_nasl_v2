#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57976);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_bugtraq_id(51377);
  script_osvdb_id(
    78459,
    78460,
    78461,
    78462,
    78463,
    78464,
    78465,
    78681,
    78682,
    78683,
    78684,
    78685,
    78686
  );

  script_name(english:"Kayako SupportSuite 3.x <= 3.70.02 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Kayako SupportSuite.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Kayako SupportSuite 3.x that is
equal to or earlier than 3.70.02 and is, therefore, affected by
multiple vulnerabilities :

  - Numerous cross-site scripting issues exist in the
    script 'staff/index.php' and in the 'LiveSupport'
    module. (PT-2011-01, PT-2011-04)

  - An input validation error exists in the administrative
    template editing interface that could allow a malicious
    user to cause arbitrary PHP code to be executed.
    (PT-2011-02)

  - An input validation error exists in the script
    'staff/index.php' that can allow an attacker to
    determine the install path of the application.
    (PT-2011-03)");

  script_set_attribute(attribute:"see_also", value:"http://en.securitylab.ru/lab/PT-2011-01");
  script_set_attribute(attribute:"see_also", value:"http://en.securitylab.ru/lab/PT-2011-02");
  script_set_attribute(attribute:"see_also", value:"http://en.securitylab.ru/lab/PT-2011-03");
  script_set_attribute(attribute:"see_also", value:"http://en.securitylab.ru/lab/PT-2011-04");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kayako Fusion 4.0 or later. The vendor has not yet released a patch for 3.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kayako:supportsuite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("kayako_supportsuite_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/kayako_supportsuite", "www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"kayako_supportsuite", port:port, exit_on_fail:TRUE);

dir         = install['dir'];
install_url = build_url(port:port,qs:dir);
version     = install['ver'];

if (version == UNKNOWN_VER)
  exit(1, "The version of Kayako SupportSuite located at "+install_url+" could not be determined.");

if (version =~ "^3(\.70)?$") exit(1, "The version of Kayako SupportSuite, "+version+", installed at "+install_url+" is not granular enough.");
if (version !~ "3\.") exit(0, "The version of Kayako SupportSuite, "+version+", installed at "+install_url+" is not 3.x.");

ver = split(version,sep:'.', keep:FALSE);
for (x=0; x<max_index(ver); x++)
  ver[x] = int(ver[x]);

if (
  ver[0] == 3 &&
  (
    (ver[1] < 70) ||
    (ver[1] == 70 && ver[2] <= 2)
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : Kayako Fusion 4.0. The vendor' +
      '\n                      has not yet released a 3.x patch.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Kayako SupportSuite "+version+" install at "+install_url+" is not affected.");
