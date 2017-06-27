#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
 script_id(11856);
 script_version("$Revision: 1.28 $");

 script_cve_id("CVE-2001-0327");
 script_bugtraq_id(6826);
 script_osvdb_id(5704);
 script_xref(name:"CERT", value:"276767");

 script_name(english:"iPlanet Web Server Enterprise Edition URL-encoded Host: Information Disclosure");
 script_summary(english:"Check for vulnerable version of iPlanet Webserver");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its self reported version number, the remote iPlanet web
server is affected by an information disclosure vulnerability wherein
a remote user can retrieve sensitive data from memory allocation
pools or cause a denial of service against the server.

*** Since Nessus solely relied on the banner of this server,
*** (and iPlanet 4 does not include the SP level in the banner),
*** to issue this alert, this may be a false positive." );
 script_set_attribute(attribute:"solution", value:
"Update to iPlanet 4.1 SP7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/17");
 script_cvs_date("$Date: 2017/03/09 14:56:42 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("www/iplanet");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

mybanner = get_http_banner(port:port);
if(!mybanner)exit(0);

if(egrep(pattern:"^Server: *Netscape-Enterprise/(4\.[01][^0-9])", string:mybanner))security_warning(port);
