#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11937);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/05/26 01:15:51 $");

 script_cve_id("CVE-2003-0973");
 script_bugtraq_id(9129);
 script_osvdb_id(2885);

 script_name(english:"mod_python < 2.7.9 / 3.0.4 Malformed Query String DoS");
 script_summary(english:"Checks for version of Python");

 script_set_attribute(attribute:"synopsis", value:"The remote web server is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the Apache mod_python module older than 2.7.9
or 3.0.4. These versions may be prone to a denial of service attacks
when handling malformed queries.");
 script_set_attribute(attribute:"see_also", value:"http://www.modpython.org/pipermail/mod_python/2003-November/014533.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to mod_python 2.7.9 / 3.0.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/04");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
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
 if(ereg(pattern:".*mod_python/(1.*|2\.([0-6]\..*|7\.[0-8][^0-9])|3\.0\.[0-3][^0-9]).*", string:serv))
 {
   security_warning(port);
 }

