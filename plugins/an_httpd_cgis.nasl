#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10016);
 script_version ("$Revision: 1.39 $");

 script_cve_id("CVE-1999-0947");
 script_bugtraq_id(762);
 script_osvdb_id(16, 11566, 11567, 11568);
 
 script_name(english:"AN-HTTPd Multiple Test CGIs Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of several CGIs");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are affected by remote
code execution vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote web server is an AN-HTTPD server which contains default CGI
scripts. At least one of these CGIs is installed on the remote server :

	cgi-bin/test.bat
	cgi-bin/input.bat
	cgi-bin/input2.bat
	ssi/envout.bat
	
It is possible to misuse them to make the remote server execute
arbitrary commands." );
 script_set_attribute(attribute:"solution", value:
"Upgrading to An-HTTPd server 1.21 or higer reportedly fixes the
problem." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/02");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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

function check(item, exp, port)
{
 local_var w, r;

 w = http_send_recv3(method:"GET", item:item, port:port);
 if (isnull(w)) exit(0);
 r = tolower(strcat(r[0], r[1], '\r\n', r[2]));
 if(exp >< r)return(1);
 return(0);
}


port = get_http_port(default:80);

cgi[0] = "/test.bat";
cgi[1] = "/input.bat";
cgi[2] = "/input2.bat";
cgi[3] = "/ssi/envout.bat";
cgi[4] = "";

for( i = 0 ; cgi[i] ; i = i + 1 )
{ 
 item = string(cgi[i], "?|type%20c:\\winnt\\win.ini");
 if(check(item:item, exp:"[fonts]", port:port)){
 	security_hole(port);
	exit(0);
	}
 item = string(cgi[i], "?|type%20c:\\windows\\win.ini");	
 if(check(item:item, exp:"[windows]", port:port)){
 	security_hole(port);
	exit(0);
	}
}
