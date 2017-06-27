#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
if(description)
{
 script_id(11592);
 script_bugtraq_id(7355);
 script_osvdb_id(50428);
 # NOTE: no CVE id assigned (jfs, december 2003)
 script_version ("$Revision: 1.18 $");
 
 script_name(english:"12Planet Chat Server Error Message Path Disclosure");
 script_summary(english:"Checks for 12Planet Chat Server path disclosure");
 
 script_set_attribute(attribute:"synopsis", value:"
The remote web server contains a Java application that is affected by
an information disclosure vulnerability.");

 script_set_attribute(attribute:"description", value:"
The remote host is running 12Planet Chat Server - a web-based chat
server written in Java.

There is a flaw in this version which allows an attacker to obtain
the physical path of the installation by sending a malformed request
to this service.

Knowing this information will help an attacker to make more focused
attacks.");
 script_set_attribute(attribute:"solution", value:"The solution is unknown.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2011/08/18 20:37:41 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
foreach port (ports)
{
 if(get_port_state(port))
 {
  r = http_send_recv3(method:"GET", port:port, item:"/qwe/qwe/index.html");
  res = strcat(r[0], r[1], '\r\n', r[2]);
  if(egrep(pattern:"java\.io\.IOException: .* [A-Za-z]:\\", string:res))
  {
    security_warning(port);
    exit(0);
  }
 }
}
