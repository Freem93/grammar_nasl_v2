#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12234);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "Terminal Services Web Detection";
 script_name(english:name["english"]);
 

 script_set_attribute(attribute:"synopsis", value:
"Terminal Services Client ActiveX is available." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be configured to facilitate the client
download of an ActiveX Terminal Services Client.  So, users can access
the web page and click a 'connect' button which will prompt a
client-side download of a .cab file which will be used to connect the
client directly to a terminal services server using Remote Desktop
Protocol -- RDP.  Of course, you will want to manually inspect this
page for possible information regarding systems offering RDP access,
system information, IP addressing information, etc." );
 script_set_attribute(attribute:"solution", value:
"Password protect access to the 'tsweb' resource." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/07");
 script_cvs_date("$Date: 2011/03/14 21:48:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Find instances of tsweb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# So, we'll first just check for http://<host>/tsweb/
# 9 times out of 10, you'll find it in this location

r = http_send_recv3(method:"GET", item: "/tsweb/", port:port, exit_on_fail: 1);

buf = strcat(r[0], r[1], '\r\n', r[2]);
if(egrep(pattern:"const L_DisconnectedCaption_ErrorMessage", string:buf)) {

	report = strcat (
'The following directory should provide a useful resource in your\n',
'pen-testing endeavors:\n',
build_url(port: port, qs: '/tsweb/'), '\n');

        security_note(port:port, extra:report);
        exit(0);
}





# Next, we'll roll through each of the cgi_dirs and check for either 
# /tsweb/<default page> or /tsweb.asp

foreach d (cgi_dirs()) {
    r = http_send_recv3(item:string(d, "/tsweb.asp"),method:"GET", port:port);
    if (isnull(r)) exit(1, "The web server did not answer");
    r2 = http_send_recv3(item:string(d, "/tsweb/"), method:"GET", port:port);
    if (isnull(r2)) exit(1, "The web server did not answer");
    buf = strcat(r[0], r[1], '\r\n', r[2]);
    buf2 = strcat(r2[0], r2[1], '\r\n', r2[2]);

    if(egrep(pattern:"const L_DisconnectedCaption_ErrorMessage", string:buf)) {
	report = string (
		"The following directory should provide a useful resource in your\n",
		"pen-testing endeavors:\n",
		string("http://", get_host_ip() , d, "\n"));

        security_note(port:port, extra:report);
        exit(0);
    }

    if(egrep(pattern:"const L_DisconnectedCaption_ErrorMessage", string:buf2)) {
 	report = string (
		"The following directory should provide a useful resource in your\n",
		"pen-testing endeavors:\n",
		string("http://", get_host_ip() , d, "/tsweb/", "\n"));

        security_note(port:port, extra:report);
        exit(0);
    }

}


