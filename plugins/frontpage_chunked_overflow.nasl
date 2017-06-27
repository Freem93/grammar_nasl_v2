#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11923);
 script_version("$Revision: 1.33 $");
 script_cve_id("CVE-2003-0822", "CVE-2003-0824");
 script_bugtraq_id(9007, 9008);
 script_osvdb_id(2800, 2952);

 script_name(english:"Microsoft FrontPage Server Extensions (fp30reg.dll) Debug Function Remote Overflow (MS03-051 / 813360)");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through FrontPage." );
 script_set_attribute(attribute:"description", value:
"The remote Microsoft FrontPage server seems vulnerable to a remote
buffer overflow.  Exploitation of this bug could give an unauthorized
user access to the machine.

The following systems are known to be vulnerable:

Microsoft Windows 2000 Service Pack 2, Service Pack 3
Microsoft Windows XP, Microsoft Windows XP Service Pack 1
Microsoft Office XP, Microsoft Office XP Service Release 1." );
 script_set_attribute(attribute:"solution", value: "Apply patch MS03-051." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS03-051 Microsoft IIS ISAPI FrontPage fp30reg.dll Chunked Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"see_also", value:
"http://technet.microsoft.com/en-us/security/bulletin/ms03-051" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/11");
 script_cvs_date("$Date: 2016/12/08 20:42:13 $");
script_xref(name:"MSFT", value: "MS03-051");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "IIS FrontPage MS03-051");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("httpver.nasl","http_version.nasl","no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ("Microsoft-IIS" >!< banner)
  exit (0);

h = make_array("Transfer-Encoding", "chunked");

r = http_send_recv3(port: port, method: "POST", 
  item: "/_vti_bin/_vti_aut/fp30reg.dll", 
  add_headers: h, 
  data: '1\r\n\r\nX\r\n0\r\n\r\n');
if (isnull(r)) exit(0);

if (! egrep(string:r[1], pattern:"^Server: Microsoft-IIS/5\.[01].*")) exit(0);

    # here we manually inspect replies to a bogus chunked request
    # an unpatched IIS 5.x server will respond to this query with a '200 OK'

r2 = http_send_recv3(port: port, method: "POST", 
   item: "/_vti_bin/_vti_aut/fp30reg.dll",
   add_headers: h,
   data: '0\r\n\r\nX\r\n0\r\n\r\n');
if (isnull(r2)) exit(0);

no404 = get_kb_item(strcat("www/no404/",port));
if (! isnull(no404) && no404 >< r2[2]) exit(0);

if (r2[0] =~ "^HTTP/1\.[01] 200 ")
 security_hole(port);
else
 set_kb_item(name:"SMB/KB813360", value:TRUE);
