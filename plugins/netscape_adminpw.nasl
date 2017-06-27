#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10468);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2014/05/26 01:40:12 $");

  script_bugtraq_id(1579);
  script_osvdb_id(367);

  script_name(english:"Netscape Administration Server /admin-serv/config/admpw Admin Password Disclosure");
  script_summary(english:"Attempts to read the Netscape configuration file admpw.");

  script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to an information disclosure flaw.");
  script_set_attribute(attribute:"description", value:
"The file /admin-serv/config/admpw is readable.

This file contains the encrypted password for the Netscape
administration server. Although it is encrypted, an attacker may
attempt to crack it by brute force.");
  script_set_attribute(attribute:"solution", value:
"Remove read access permissions for this file and/or stop the Netscape
administration server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("www/netscape-commerce", "www/netscape-fasttrack", "www/iplanet", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if (! sig) sig = get_http_banner(port: port);
if (! sig) exit(1, "No HTTP banner on port "+port);
if ("Netscape" >!< sig && "SunONE" >!< sig ) exit(0);

res = is_cgi_installed3(item:"/admin-serv/config/admpw", port:port);
if(res)security_warning(port);
