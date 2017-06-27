#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11622);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2002-1157");
 script_bugtraq_id(6029);
 script_osvdb_id(2107);

 script_name(english:"Apache mod_ssl Host: Header XSS");
 script_summary(english:"Checks for version of mod_ssl");

 script_set_attribute(attribute:"synopsis", value:"The remote web server module has a cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to the web server banner, the version of mod_ssl running on
the remote host has a cross-site scripting vulnerability. A remote
attacker could exploit this by tricking a user into requesting a
maliciously crafted URL, resulting in stolen credentials.

Note that several Linux distributions (such as RedHat) patched the old
version of this module.  Therefore, this might be a false positive. 
Please check with your vendor to determine if you really are affected by
this flaw.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Oct/384");
 script_set_attribute(attribute:"solution", value:"Upgrade to mod_ssl 2.8.10 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "cross_site_scripting.nasl");
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

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port));
if(!banner || backported)exit(0);

serv = strstr(banner, "Server");
if("Apache/" >!< serv ) exit(0);
if("Apache/2" >< serv) exit(0);
if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.[0-9][^0-9])).*", string:serv))
{
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
