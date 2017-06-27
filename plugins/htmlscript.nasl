#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10106);
 script_bugtraq_id(2001);
 script_osvdb_id(90);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-1999-0264");
 
 script_name(english:"Miva htmlscript Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI that may allow any file
to be accessed." );
 script_set_attribute(attribute:"description", value:
"The 'htmlscript' cgi is installed. This CGI has
a well known security flaw that lets anyone read arbitrary
files with the privileges of the HTTP daemon (root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"Remove the 'htmlscript' script from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/01/27");
 script_cvs_date("$Date: 2011/03/14 21:48:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks for the presence of /cgi-bin/htmlscript");
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
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

foreach dir (cgi_dirs())
{
 data = string(dir, "/htmlscript?../../../../../../../../../etc/passwd");
 r = http_send_recv3(method:"GET",item:data, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_hole(port);
 	exit(0);
	}
}

