#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>,
# with the impulsion of H D Moore on the Nessus Plugins-Writers list

include("compat.inc");

if (description)
{
 script_id(10888);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2002-0082");
 script_bugtraq_id(4189);
 script_osvdb_id(756);

 script_name(english:"Apache mod_ssl i2d_SSL_SESSION Function SSL Client Certificate Overflow");
 script_summary(english:"Checks for version of mod_ssl");

 script_set_attribute(attribute:"synopsis", value:"The remote web server module has a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to the web server banner, the remote host is using a
vulnerable version of mod_ssl. This version has a buffer overflow
vulnerability. A remote attacker could exploit this issue to execute
arbitrary code.

*** Some vendors patched older versions of mod_ssl, so this *** might
be a false positive. Check with your vendor to determine *** if you
have a version of mod_ssl that is patched for this *** vulnerability.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Feb/376");
 script_set_attribute(attribute:"solution", value:"Upgrade to mod_ssl 2.8.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/08");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport", "www/apache");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port));
if(!banner || backported)exit(0);

serv = strstr(banner, "Server");
if("Apache/" >!< serv ) exit(0);
if("Apache/2" >< serv) exit(0);
if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.[0-6][^0-9])).*", string:serv))
{
  security_hole(port);
}
