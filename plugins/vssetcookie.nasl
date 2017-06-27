#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/9/2009)

include("compat.inc");

if (description)
{
  script_id(11731);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_cve_id("CVE-2002-0236");
  script_bugtraq_id(3784);
  script_osvdb_id(4261);

  script_name(english:"Lucent VitalNet VsSetCookie.exe Unauthorized Access");
  script_summary(english:"Checks for the VsSetCookie.exe file");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has an unauthorized access
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VsSetCookie.exe CGI exists on the remote web server. Some versions
of this file have an unauthorized access vulnerability. Making a
request similar to :

 http://www.example.com/cgi-bin/VsSetCookie.exe?vsuser=<user_name>

will result in full access if a valid username is provided. Please
note Nessus solely relied on the existence of this CGI in reporting
this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Feb/60");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2016 John Lampe");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   u = string(dir, "/VsSetCookie.exe");
   if(is_cgi_installed_ka(item: u, port:port)) {
        report = '\n'+build_url(qs:u, port:port)+' was found.\n';
	security_hole(port:port, extra:report);
  	break;
   }
}

