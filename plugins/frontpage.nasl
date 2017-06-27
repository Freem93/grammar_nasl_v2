#
# (C) Tenable Network Security, Inc.
#

# Modified by John Lampe...j_lampe@bellsouth.net to add "open service" call and
# add 2 more files to look for


include("compat.inc");

if(description)
{
 script_id(10077);
 script_version ("$Revision: 1.55 $");
 script_cvs_date("$Date: 2014/06/09 20:25:40 $");

 script_cve_id("CVE-2000-0114");
 script_osvdb_id(67);

 script_name(english: "Microsoft FrontPage Extensions Check");

 script_set_attribute(attribute:"synopsis", value:
"FrontPage extensions are enabled." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running with the FrontPage
extensions.  

FrontPage allows remote web developers and administrators to modify
web content from a remote location.  While this is a fairly typical
scenario on an internal local area network, the FrontPage extensions
should not be available to anonymous users via the Internet (or any
other untrusted 3rd party network)." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for the presence of Microsoft FrontPage extensions");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (get_kb_item("www/" + port + "/no404") )
 exit(0, "The web server on port "+port+" does not return 404 codes.");

r = http_send_recv3( port: port, method: "GET", 
    		     exit_on_fail: 1,
    		     item:"/_vti_bin/shtml.dll/_vti_rpc");
if (r[0] !~ "^HTTP/.\.. 200 ")
 exit(0, build_url(qs:"/_vti_bin/shtml.dll/_vti_rpc", port: port) + 'cannot be read.');

h = make_array( "Accept", "*/*", 
    		"User-Agent", "MSFrontPage/4.0",
		"Content-Type", "application/x-www-form-urlencoded",
		"MIME-Version", "1.0",
		"X-Vermeer-Content-Type", "application/x-www-form-urlencoded");
# Content-Length=58??

r = http_send_recv3( port: port, method: "POST", 
    		     item: "/_vti_bin/shtml.dll/_vti_rpc",
		     data: 'method=open+service%3a3%2e0%2e2%2e1105&service%5fname=%2f\r\n',
		     exit_on_fail: 1,
		     add_headers: h);

if(! egrep(pattern:"^<li>msg=The user '\(unknown\)'", string:r[2]) &&
   egrep(pattern:".*x-vermeer-rpc*", string: r[1]))
{
  msg = egrep(pattern:".*<li>msg=.*'.*'.*'open service'.*", string: r[2]);
  if ( msg )
  {	
   user = ereg_replace(pattern:".*<li>msg=.*'(.*)'.*'open service'.*", string: r[2], replace:"\1");
   myreport = 'The remote frontpage server leaks information regarding the name of the anonymous user.\r\n';
   myreport += 'By knowing the name of the anonymous user, more sophisticated attacks may be launched.\r\n';
   myreport += 'We could gather that the name of the anonymous user is : ' + user;
   set_kb_item(name:"www/frontpage", value:TRUE);

   report = '\n' + myreport;
   security_note (port:port, extra:report);
   exit(0);
  }
}

if (thorough_tests)
{
 files = make_list( "/_vti_bin/_vti_adm/admin.dll",
      		   "/_vti_bin/_vti_aut/author.dll",
		   "/_vti_bin/shtml.exe/_vti_rpc" );
 foreach file (files)
 {
   if (is_cgi_installed3(item: file, port:port))
   {
     name = strcat('www/no404/', port);
     no404 = get_kb_item(name);
     r = http_send_recv3(item: file, method: 'POST', port:port, exit_on_fail: 1);
     if (r[0] =~ "^HTTP/1\.[01] +200 ")
     {
       if(no404 && tolower(no404) >< tolower(r[0]+'\r\n'+r[1] + '\r\n\r\n'+r[2]))
         exit(0);
       security_note(port);
       set_kb_item(name:"www/frontpage", value:TRUE);
       exit(0);
     }
   }
}
}



