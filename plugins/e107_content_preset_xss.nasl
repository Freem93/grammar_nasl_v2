#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66395);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2013-2750");
  script_bugtraq_id(58841);
  script_osvdb_id(91981);

  script_name(english:"e107 content_preset.php URI XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 installed on the remote host is affected by a
cross-site scripting vulnerability because it fails to properly sanitize
user input passed in the URI to the 'content_preset.php' script.  An
attacker may be able to leverage this to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Apr/19");
  script_set_attribute(attribute:"see_also", value:"http://e107.org/news.php?extend.890.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107","www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "e107",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

xss_test = "<%00script%00>alert(" + unixtime() + ")</script>";
pattern = "create a new preset data tag of type : ";

xss_chk = hexstr(pattern + xss_test);
xss_chk = str_replace(string:xss_chk, find:"253030", replace:"00");

url = '/e107_plugins/content/handlers/content_preset.php?' + xss_test;

res = http_send_recv3(
  method : "GET",
  item   : dir + url,
  port   : port,
  exit_on_fail : TRUE
);

if (xss_chk >< hexstr(res[2]))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  output = extract_pattern_from_resp(string:res[2], pattern:'ST:'+pattern);

  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue using the following request :' +
      '\n' +
      '\n' + install_url + url +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\nThis produced the following response :' +
        '\n' +
        '\n' + snip +
        '\n' + output +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);
