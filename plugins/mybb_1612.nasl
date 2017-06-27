#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72906);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id("CVE-2013-7275", "CVE-2013-7288");
  script_bugtraq_id(64570);
  script_osvdb_id(101542, 101543, 101544, 101545);

  script_name(english:"MyBB < 1.6.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MyBB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MyBB install hosted on the remote
web server is affected by multiple vulnerabilities :

  - A cross-site scripting flaw exists in misc.php due to
    improper validation of input when generating a small
    popup list of smilies. This allows a remote attacker to
    create a specially crafted request to execute arbitrary
    script code in a user's browser session within the trust 
    relationship between the browser and server.
    CVE-2013-7275)

  - A cross-site scripting vulnerability exists in the
    mycode_parse_video() function in the 
    inc/class_parser.php script due to improper validation
    of Yahoo video URLs before returning them to a user.
    This allows a remote attacker to create a specially
    crafted request to execute arbitrary script code in a
    user's browser session within the trust relationship
    between the browser and server. (CVE-2013-7288)

  - A SQL injection vulnerability exists in the
    admin/modules/config/smilies.php script due to improper
    sanitization of user-supplied input when mass
    editing smilies. A remote attacker can exploit this
    issue to manipulate SQL queries, resulting in the
    disclosure of sensitive information and modification of
    data. (VulnDB 101542)

  - A SQL injection vulnerability exists in the
    akismet_admin() function in inc/plugins/akismet.php due
    to improper sanitization of user-supplied input when
    deleting posts. A remote attacker can exploit this issue
    to manipulate SQL queries, resulting in the disclosure
    of sensitive information and modification of data.
    (VulnDB 101543)

Note that Nessus has not tested for these issues but has instead
relied on the application's self-reported version number.");
  # http://blog.mybb.com/2013/12/16/mybb-1-6-12-released-security-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ecc7084");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.6.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/MyBB", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
install_url = build_url(port:port, qs:install['path']);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "1.6.12";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
