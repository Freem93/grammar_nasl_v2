#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43827);
  script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_bugtraq_id(37637);
  script_osvdb_id(61512);
  script_xref(name:"Secunia", value:"37822");

  script_name(english:"Snitz Forums 2000 active.asp HTTP X-Forwarded-For Header SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an ASP script that is susceptible to a
SQL injection attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Snitz Forums 2000 hosted on the remote host fails to
sanitize input to the 'X-Forwarded-For' header in the 'active.asp'
script when called with the 'AllRead' POST parameter set to 'Y'
before using it to construct a database query.

An unauthenticated, remote attacker can leverage this issue to
manipulate SQL queries and, for example, modify data or uncover
sensitive information from the application's database."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("snitz_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/snitz");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0, "The web server on port "+port+" does not support ASP scripts.");


# Test an install.
disable_cookiejar();                   # note strictly needed

install = get_install_from_kb(appname:'snitz', port:port);
if (isnull(install)) exit(1, "Snitz Forums 2000 wasn't detected on port "+port+".");
dir = install['dir'];


# Make sure the affected script exists.
url = dir + "/active.asp";

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (
  "- Active Topics" >!< res[2] &&
  '//defaultStatus = "You last loaded this page on "' >!< res[2]
) exit(0, "The 'active.asp' script could not be found in the Snitz Forums 2000 install at "+build_url(port:port, qs:dir+"/")+".");


# Try to exploit the flaw to generate a SQL syntax error.
exploit = "'" + SCRIPT_NAME;
postdata = 'AllRead=Y';

req = http_mk_post_req(
  port        : port,
  item        : url,
  data        : postdata,
  add_headers : make_array(
    "Content-Type", "application/x-www-form-urlencoded",
    "X-Forwarded-For", exploit
  )
);
res = http_send_recv_req(port:port, req:req);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");


# There's a problem if we see an error with our exploit.
if (
  "error '80040e14'" >< res[2] &&
  exploit+"' WHERE M_NAME = " >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    req_str = http_mk_buffer_from_req(req:req);

    report = '\n' +
      'Nessus was able to verify the vulnerability using the following\n' +
      'request :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      req_str + '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, "The Snitz Forum 2000 install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
