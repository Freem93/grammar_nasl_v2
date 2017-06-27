#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11750);
 script_bugtraq_id(6607);
 script_version ("$Revision: 1.12 $");
  script_name(english:"Psunami.CGI Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is hosting Psunami.CGI
There is a flaw in this CGI which allows an attacker to execute 
arbitrary commands with the privileges of the HTTP server by making a
request like :
	
	/psunami.cgi?action=board&board=1&topic=|id|" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/17");
 script_cvs_date("$Date: 2011/03/15 19:22:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for Psunami.CGI");
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			extra_dirs:make_list("/shop"),
			check_request:"/psunami.cgi?file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
