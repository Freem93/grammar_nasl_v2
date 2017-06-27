#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59569);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id("CVE-2012-0389");
  script_bugtraq_id(51401);
  script_osvdb_id(78242);
  script_xref(name:"EDB-ID", value:"18447");

  script_name(english:"MailEnable ForgottenPassword.aspx Username Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The webmail client bundled with MailEnable is affected by a
cross-site scripting vulnerability in the ForgottenPassword.aspx
script.  The 'Username' parameter fails to properly sanitize user-
supplied input.  Successful exploitation would allow an attacker to
steal cookies used for webmail access."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nerv.fi/CVE-2012-0389.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/kb/Content/Article.asp?ID=me020567");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to MailEnable 5.53 / 6.03 or later.

Alternatively, those with MailEnable 4 can apply the fix provided in
the referenced URL."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mailenable_webmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mailenable_webmail");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:"mailenable_webmail", port:port, exit_on_fail:TRUE);
dir = install["dir"];
dir = ereg_replace(pattern:"^(.*)/[^/]+\.aspx", replace:"\1", string:dir);

# Version 4.x will timeout when accessing ForgottenPassword.aspx
# unless we first establish a new session.
new_session = http_send_recv3(method:"GET", item:install["dir"], port:port, exit_on_fail:TRUE);

# Versions 4.x
if ('ForgottenPassword.aspx?Username="' >< new_session[2])
{
  xss_test = '"};alert(/' + SCRIPT_NAME + '-' + unixtime() + '/);{"';
}
# Versions 5.x/6.x
else xss_test = "'};alert(/" + SCRIPT_NAME + "-" + unixtime() + "/);{'";

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : "/forgottenpassword.aspx",
  qs       : 'username=' + urlencode(str:xss_test),
  pass_str :  xss_test,
  pass_re  : 'function PageLoad()',
  silent   : TRUE
);
if (exploit)
{
  if (report_verbosity > 0)
  { 
    report = 
      '\n' + 'Nessus was able to exploit the issue using the following sequence of' +
      '\n' + 'URLs :' +
      '\n' +
      '\n  ' + build_url(port:port, qs:install["dir"]) +
      '\n  ' + build_url(port:port, qs:dir+"/forgottenpassword.aspx?Username="+urlencode(str:xss_test)) +
      '\n';
  }
  security_warning(port:port, extra:report);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "MailEnable WebMail", build_url(qs:install["dir"], port:port));
