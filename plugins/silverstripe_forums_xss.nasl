#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44332);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2010-1593");
  script_bugtraq_id(37923);
  script_osvdb_id(61921);
  script_xref(name:"Secunia", value:"38347");

  script_name(english:"SilverStripe Forums Module 'Search' Parameter XSS");
  script_summary(english:"Checks for an XSS issue in the 'Search' parameter of the forums module.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The SilverStripe CMS install hosted on the remote web server includes
a version of the Forums module that is affected by a cross-site
scripting vulnerability.  User input to the 'Search' parameter is not
sanitized before being used to generate dynamic HTML.

An attacker can exploit this flaw to execute arbitrary script code in a
user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jan/445");
  script_set_attribute(attribute:"see_also", value:"http://www.silverstripe.org/silverstripe-2-3-5-released/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27db2eee");
  script_set_attribute(attribute:"solution", value:"Upgrade to SilverStripe Forums module 0.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:silverstripe:silverstripe");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("silverstripe_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/silverstripe");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(1, "The web server on port "+port+" does not support PHP.");

install = get_install_from_kb(appname:'silverstripe', port:port);
if (isnull(install)) exit(1, "SilverStripe CMS wasn't detected on port "+port+".");

res = http_send_recv3(method:"GET", item:install['dir']+'/forums/', port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

data = strstr(res[2], '<td class="even lastPost">') - '<td class="even lastPost">';

matches = eregmatch(string:data, pattern:'<a class="topicTitle" href=.*/show/.*>(.*)</a>');

topic = matches[1];
exploit = '"onMouseOver="alert(\''+topic+' '+SCRIPT_NAME+unixtime()+'\')"';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(install['dir']),
  cgi:"/forums/search/",
  qs:"Search="+urlencode(str:exploit),
  pass_str:'<a href="forums/search/?Search='+exploit+'" class="current"',
  ctrl_re:'SilverStripe Open Source CMS'
);

if (!exploited)
{
  install_url = build_url(qs:install['dir']+'/',port:port);
  exit(0, "The SilverStripe CMS install at " + install_url + " is not affected.");
}

