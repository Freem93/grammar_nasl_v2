#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
  script_id(10575);
  script_version("$Revision: 1.41 $");
  script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2002-1717");
  script_bugtraq_id(4078);
  script_osvdb_id(473);

  script_name(english:"Microsoft IIS Multiple .cnf File Information Disclosure");
  script_summary(english:"Check for existence of world-readable .cnf files");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IIS web server may allow a remote user to retrieve its
installation path via GET requests to the files 'access.cnf',
'botinfs.cnf', 'bots.cnf' or 'linkinfo.cnf' in the '/_vti_pvt'
directory. This is not the default configuration.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Feb/174");
  script_set_attribute(attribute:"solution", value:
"If you do not need .cnf files, then delete them. Otherwise use
suitable access control lists to ensure that the .cnf files are not
world-readable by anonymous users.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"Copyright (C) 2000-2016 John Lampe <j_lampe@bellsouth.net>");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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
if ( get_kb_item("www/" + port + "/no404" ) )  exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port)) {
   fl[0] = "/_vti_pvt%5caccess.cnf";
   fl[1] = "/_vti_pvt%5csvcacl.cnf";
   fl[2] = "/_vti_pvt%5cwriteto.cnf";
   fl[3] = "/_vti_pvt%5cservice.cnf";
   fl[4] = "/_vti_pvt%5cservices.cnf";
   fl[5] = "/_vti_pvt%5cbotinfs.cnf";
   fl[6] = "/_vti_pvt%5cbots.cnf";
   fl[7] = "/_vti_pvt%5clinkinfo.cnf";

   for(i = 0 ; fl[i] ; i = i + 1)
   {
    if(is_cgi_installed_ka(item:fl[i], port:port)){
	res = http_keepalive_send_recv(data:http_get(item:fl[i], port:port), port:port, bodyonly:1);
        report = string(
          "\n",
          "Requesting '", fl[i], "' produced the following data :\n",
          "\n",
          res
        );
        security_warning(port:port, extra:report);
	exit(0);
	}
   }
}
