#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10498);
 script_version("$Revision: 1.46 $");
 script_cvs_date("$Date: 2015/11/18 21:03:57 $");

 script_bugtraq_id(12141);
 script_osvdb_id(397, 5646, 12806);
 script_xref(name:"OWASP", value:"OWASP-CM-001");
 
 script_name(english:"Web Server HTTP Dangerous Method Detection");
 script_summary(english:"Verifies the access rights to the web server (PUT, DELETE)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows the PUT and/or DELETE method.");
 script_set_attribute(attribute:"description", value:
"The PUT method allows an attacker to upload arbitrary web pages on 
the server. If the server is configured to support scripts like ASP
or PHP, it will allow the attacker to execute code with the privileges
of the web server.

The DELETE method allows an attacker to delete arbitrary content from
the web server.");
 script_set_attribute(attribute:"solution", value:
"Disable the PUT and/or DELETE method in the web server configuration.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft IIS WebDAV Write Access Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/30");
 script_set_attribute(attribute:"vuln_publication_date", value:"1994/01/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function exists(file, port)
{
 local_var r;

 r = http_send_recv3(port: port, method: 'GET', item: file);
 if (isnull(r)) return NULL;

 if (r[0] =~ "^HTTP/[0-9]\.[0-9] 200 " && 
     ("A quick brown fox jumps over the lazy dog" >< r[2])  )
   return 1;

 return 0;
}


delete = upload = 0;

port = get_http_port(default:80, embedded: 0);

r = http_send_recv3(port: port, method: "OPTIONS", item: "*");
allow = egrep(string: r[1], pattern: "^Allow:", icase: 1);

name = NULL;

for (i=1; i <= 20 && isnull(name); i++)
{
 rad = rand_str(charset: "aegnoprsvw", length: 6);
 name = strcat("/", rad, i, ".html");
 if (exists(file: name, port:port) != 0) name = NULL;
}

if (isnull(name)) exit(0);

c = crap(length:77, data:"A quick brown fox jumps over the lazy dog");

req_put = http_mk_put_req(port:port, item:name, data:c);
r       = http_send_recv_req(port:port, req:req_put, username:"", password:"");

if (exists(port:port, file:name))
  upload = 1;
else if (" 401 " >< r[0] && "PUT" >< allow)
  upload = 2;
else
  upload = 0;


if (upload == 1)
{
 req_del = http_mk_delete_req(port:port, item:name);
 r       = http_send_recv_req(port:port, req:req_del, username:"", password:"");

 if (r[0] =~ "^HTTP/[0-9]\.[0-9] 20[04] ")
 {
  if (exists(port:port, file:name) == 0)
    delete = 1;
  else if (" 401 " >< r[0] && " is disabled " >!< r[0] && "DELETE" >< allow)
    delete = 2;
  else
    delete = 0;
 }
}


# if we were not able to test DELETE and PUT we just quit
if (delete != 1 && upload != 1) exit(0);


report = "";

if (delete == 1 || upload == 1)
{
 if (delete == 1 && upload == 1) s = 's';
 else s = '';
 report += strcat('\nThe remote web server supports the following method', s, ' :\n\n');

 if (upload == 1)
   report += strcat('  - PUT (the file \'', name, '\' has been uploaded)\n');
 if (delete == 1)
   report += strcat('  - DELETE (the file \'', name, '\' has been deleted)\n');

 if (report_verbosity > 1)
 {
   if (delete == 1 && upload == 1) finding = 'these findings';
   else finding = 'this finding';
   report = string(
     report,
     "\n",
     "The following request", s, " may help to validate ", finding, " :\n",
     "\n",
     crap(data:"-", length:60), "\n"
   );

   if (upload == 1)
   {
     req_str = http_mk_buffer_from_req(req:req_put);
     report = string(
       report,
       req_str, "\n",
       crap(data:"-", length:60), "\n"
     );
   }
   if (delete == 1)
   {
     req_str = http_mk_buffer_from_req(req:req_del);
     report = string(
       report,
       req_str, "\n",
       crap(data:"-", length:60), "\n"
     );
   }
 }
}

if (delete == 2 || upload == 2)
{
 if (delete == 2 && upload == 2) s = 's are';
 else s = ' is';
 report += strcat('\nThe following method', s, ' available on the web server, but Nessus\nwas unable to test them directly :\n\n');

 if (upload == 2)
   report += '  - PUT\n';
 if (delete == 2)
   report += '  - DELETE\n';
}

if (report)
{
  security_hole(port:port, extra:report);
  if (COMMAND_LINE) display(report);
}

