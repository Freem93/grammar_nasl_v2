#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10299);
 script_version("$Revision: 1.48 $");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");

 script_cve_id("CVE-1999-0039");
 script_bugtraq_id(374);
 script_osvdb_id(235);
 script_xref(name:"CERT-CC", value:"CA-1997-12");
 
 script_name(english:"IRIX webdist.cgi Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of webdist.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
code execution.");
 script_set_attribute(attribute:"description", value:
"The 'webdist.cgi' CGI is installed.  This script has a well-known
security flaw that lets anyone execute arbitrary commands with the
privileges of the web server user id.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/May/18");
 script_set_attribute(attribute:"solution", value:"Remove this CGI.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/05/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

http_check_remote_code(
  extra_dirs:"",
  check_request:"/webdist.cgi?distloc=;id",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);
