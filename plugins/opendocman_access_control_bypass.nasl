#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(13847);
 script_bugtraq_id(10807);
 script_version("$Revision: 1.9 $");

 script_name(english:"OpenDocMan Access Control Bypass");
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that could allow unauthorized
access to certain documents." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenDocMan, an open source document management
system.

There is a flaw in the remote version of this software that could allow an
attacker with a given account to modify the content of some documents
he would otherwise not have access to." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenDocMan 1.2.0" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/26");
 script_cvs_date("$Date: 2011/12/15 00:11:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if OpenDocMan is present");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);

foreach dir (cgi_dirs())
{
 url = string(dir,"/index.php");
 res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);
 
 if( "OpenDocMan" >< res && egrep(pattern:"<h5> OpenDocMan v(0\.|1\.[01]\.)", string:res[2]) ) 
 {
    	security_warning(port);
	exit(0);
 }
}
