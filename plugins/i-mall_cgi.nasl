#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15750);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-2275");
 script_bugtraq_id(10626);
 script_osvdb_id(7461);
 script_xref(name:"Secunia", value:"11972"); 

 script_name(english:"Webman I-Mall i-mall.cgi Arbitrary Command Execution");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a CGI script that is affected by a
remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The script i-mall.cgi is installed.  Some versions of this script are
vulnerable to remote command execution flaw, due to insufficient user
input sanitization to the 'p' parameter of the i-mall.cgi script.
A malicious user can pass arbitrary shell commands on the remote 
server through this script." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/exploits/5UP0715FPC.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/29");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the presence of i-mall.cgi");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');


if ( thorough_tests )
{
 extra_list = make_list ("/i-mall");
}
else
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/i-mall.cgi?p=|id|",
			check_result:"uid=[0-9]+.* gid=[0-9]+.*",
			command:"id" );
