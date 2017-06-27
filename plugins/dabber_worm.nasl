#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12266);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2014/05/25 23:45:39 $");

 script_name(english:"W32.Dabber Worm Detection");
 script_summary(english:"W32.Dabber worm detection");

 script_set_attribute(attribute:"synopsis", value:"The remote host has been compromised.");
 script_set_attribute(attribute:"description", value:
"The W32.Dabber worm is listening on this port. W32.Dabber propagates
by exploiting a vulnerability in the FTP server component of
W32.Sasser.Worm and its variants.

It installs a backdoor on infected hosts and tries to listen on port
9898. If the attempt fails, it tries to listen on ports 9899 through
9999 in sequence until it finds an open port.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?839c7128");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-011");
 script_set_attribute(attribute:"solution", value:
"- Disable access to port 445 and Dabber remote shell by
   using a firewall.

 - Apply Microsoft MS04-011 patch.

 - Update your virus definitions.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/10");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");

 script_dependencies("find_service2.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(5554);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
# The script code starts here
#
sasser_port = 5554;
dabber_ports = make_list();

for ( port = 9898 ; port <= 9999 ; port ++ )
{
	dabber_ports = make_list(dabber_ports, port);
}

if (get_port_state(sasser_port))
{
	if (open_sock_tcp(sasser_port))
	{
		foreach port (dabber_ports)
		{
			if (get_port_state(port))
			{
				soc=open_sock_tcp(port);
				if (soc)
				{
					buf = string("C");
					send(socket:soc, data:buf);
					data_root = recv(socket:soc, length:2048);
				        close(soc);

					if(data_root)
  					{
						security_hole(port);
					}
				}
			}
		}
	}
}
exit(0);
