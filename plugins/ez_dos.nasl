#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14682);
  script_version("$Revision: 1.12 $");

  script_bugtraq_id(11129);
  script_osvdb_id(9728);

  script_name(english:"eZ/eZphotoshare Connection Saturation Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote application is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host runs eZ/eZphotoshare, a service for sharing and exchanging 
digital photos.

This version is vulnerable to a denial of service attack.

An attacker could prevent the remote service from accepting requests 
from users by quickly establishing multiple connections from the same host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/06");
 script_cvs_date("$Date: 2012/12/10 23:41:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"x-cpe:/a:ezmeeting:eZphotoshare");
script_end_attributes();

  script_summary(english:"Checks for denial of service in eZ/eZphotoshare");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_require_ports(10101);
  exit(0);
}


port = 10101;

if (! get_port_state(port)) exit(0, "TCP port "+port+" is closed.");

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");
  
  s[0] = soc;

  #80 connections should be enough, we just add few one :)
  for (i = 1; i < 90; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_warning(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);


