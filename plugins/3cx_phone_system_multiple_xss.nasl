#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40613);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/09/22 15:18:21 $");

  script_cve_id("CVE-2008-6894");
  script_bugtraq_id(32709);
  script_osvdb_id(50599);
  script_xref(name:"Secunia",value:"33060");

  script_name(english:"3CX Phone System login.php Multiple Parameter XSS");
  script_summary(english:"Checks for XSS flaws in login.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting issues.");
  script_set_attribute(attribute:"description", value:
"3CX Phone System for Windows, a software-based IP PBX, is installed on
the remote host.  The installed version fails to sanitize input to the
'fName' and 'fPassword' parameters in 'login.php' before using it to
generate an HTML response dynamically.  An unauthenticated remote
attacker may be able to leverage these issues to inject arbitrary HTML
or script code into a user's browser to be executed within the security
context of the affected site. 

Although Nessus has not checked for them, the installed version is also
likely to be affected by several other vulnerabilities, including denial
of service, sniffing of administrator's session ID, and path
disclosure.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Dec/178");
  script_set_attribute(attribute:"see_also", value:"http://wiki.3cx.com/change-log/build-history-changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade to 3CX Phone System for Windows 7.0.3775 (RC) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 5481);
  script_require_keys("Settings/ParanoidReport", "www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb :
# 3CX Phone System is only
# available for Windows.

if(report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (os && "Windows" >!< os) exit(0, "The remote OS is not Windows.");
}

port =  get_http_port(default:5481);

if (!can_host_php(port:port))  exit(0, "The web server does not support PHP scripts.");

xss = string('"><script>alert(',"'",SCRIPT_NAME,"'",')</script>');
exploit = string("/login.php?fName=",xss);

res = http_send_recv3(port:port, method:"GET", item:exploit);
if (isnull(res)) exit(1, "The web server failed to respond.");

if (thorough_tests && xss >!< res[2])
{
  exploit = string("/login.php?fPassword=",xss);
  res = http_send_recv3(port:port, method:"GET", item:exploit);
  if (isnull(res)) exit(1, "The web server failed to respond.");
}

if (
  (
    string('name="fName" style="width:206px" value="',xss) >< res[2] ||
    string('name="fPassword" style="width:206px" value="',xss) >< res[2]
  ) &&
  '>3CX - Login page</' >< res[2]
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to exploit the cross-site scripting flaw using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:exploit), "\n"
      );
      security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The remote host is not affected.");
