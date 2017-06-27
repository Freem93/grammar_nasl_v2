#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14684);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-2422", "CVE-2004-2423");
 script_bugtraq_id(11106);
 script_osvdb_id(9552, 9553, 9554);
 
 script_name(english:"Ipswitch IMail Server < 8.13 Multiple Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple denial of service
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IMail web interface.  This version contains 
multiple buffer overflows.

An attacker could use these flaws to remotely crash the service 
accepting requests from users, or possibly execute arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://support.ipswitch.com/kb/IM-20040902-DM01.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IMail 8.13 or laster, as this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/03");
 script_cvs_date("$Date: 2012/07/20 18:51:35 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:imail");
 script_end_attributes();

 
 script_summary(english:"Checks for version of IMail web interface");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include ("http_func.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
if ( ! banner ) exit(0);
serv = egrep(string: banner, pattern: "^Server:.*");
if(ereg(pattern:"^Server:.*Ipswitch-IMail/([1-7]\..*|(8\.(0[0-9]?[^0-9]|1[0-2][^0-9])))", string:serv))
   security_warning(port);
