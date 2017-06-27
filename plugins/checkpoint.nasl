#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10044);
 script_version ("$Revision: 1.21 $");
 script_name(english:"Check Point FireWall-1 Identification");
 script_summary(english:"Determines if the remote host is a FW/1");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote firewall is leaking information."
 );
 script_set_attribute( attribute:"description",  value:
"The remote host has the three TCP ports 256, 257, and 258
open. It's very likely that this host is a Check Point FireWall/1.
A remote attacker could use this information to mount further attacks." );
  # http://web.archive.org/web/20030217171518/http://www.phoneboy.com/fom-serve/cache/405.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?f189d2b7"
 );
 script_set_attribute(attribute:"solution", value:
"Do not allow any connections on the firewall itself, except for the
firewall protocol, and allow that for trusted sources only.

If you have a router that performs packet filtering, add an ACL
that disallows the connection to these ports for unauthorized
systems." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/07/27");
 script_cvs_date("$Date: 2012/09/27 21:25:22 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:checkpoint:firewall-1");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
 script_require_ports(256,257,258);
 exit(0);
}

#
# The script code starts here
#

if((get_port_state(256))&&
   (get_port_state(257))&&
   (get_port_state(258)))
{
 # open a socket on these ports to check
 # (get_port_state() returns TRUE when the 
 # host has not been scanned
 
 soc1 = open_sock_tcp(256);
 if(!soc1)exit(0);
 close(soc1);
 
 soc2 = open_sock_tcp(257);
 if(!soc2)exit(0);
 close(soc2);

 soc3 = open_sock_tcp(258);
 if(!soc3)exit(0);
 close(soc3);
 
 # post the warning on every port
 security_warning(256);
 security_warning(257);
 security_warning(258); 
}
