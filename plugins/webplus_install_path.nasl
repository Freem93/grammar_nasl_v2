#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/7/2009)

include("compat.inc");

if(description)
{
  script_id(12074);
  script_version ("$Revision: 1.13 $");
  script_osvdb_id(53354);
  script_cvs_date("$Date: 2013/01/25 01:19:11 $");

 script_name(english:"TalentSoft Web+ webplus.exe Path Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Web+ Application Server. 

The version of Web+ installed on the remote host reveals the physical
path of the application when it receives a script file error." );
 script_set_attribute(attribute:"see_also", value:"http://www.talentsoft.com/Issues/IssueDetail.wml?ID=WP197" );
 script_set_attribute(attribute:"solution", value:
"Apply the vendor-supplied patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/24");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks for Webplus install path disclosure");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2013 David Kyger");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);

foreach dir (cgi_dirs()) {
  req = http_get(item:string(dir, "/webplus.exe?script=", SCRIPT_NAME), port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ("Web+ Error Message" >< buf)
  {
    if (report_verbosity > 0) {
      path = strstr(buf, " '");
      path = ereg_replace(pattern:" and.*$", replace:"",string:path);

      report = string("\nPath : ", path, "\n");
    }
    else report = desc["english"];

    security_warning(port:port, extra:report);
  }
}
