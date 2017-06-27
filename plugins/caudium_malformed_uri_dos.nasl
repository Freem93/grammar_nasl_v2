#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15625);
 script_bugtraq_id(11567);
 script_osvdb_id(11255);
 script_xref(name:"Secunia", value:"13040");

 script_version("$Revision: 1.13 $");
 script_name(english:"Caudium Web Server Malformed URI Remote DoS");
 script_summary(english:"Checks for version of Caudium");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description", value:
"The remote host is running the Caudium Web Server.

The remote version of this software is vulnerable to an attack wherein
a malformed URI causes the web server to stop responding to requests.

A remote attacker could disable this service by issuing a specially
crafted HTTP GET request." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Dec/455"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?6688e206"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Caudium 1.4.4 RC2 or newer."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/15");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server: Caudium/(0\..*|1\.[0-3]\..*|1\.4\.[0-3])", string:serv) )
 {
   security_warning(port);
 }
