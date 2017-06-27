#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12252);
 script_version("$Revision: 1.18 $");

 script_name(english: "Korgo Worm Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is probably infected with the Korgo worm." );
 script_set_attribute(attribute:"description", value:
"Nessus found that TCP ports 113 and 3067 are open.
The Korgo worm is known to open a backdoor on these ports.
It propagates by exploiting the LSASS vulnerability on TCP port 445 
(as described in Microsoft Security Bulletin MS04-011)

** Note that Nessus did not try to talk to the backdoor,
** so this might be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0648f11d" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-011" );
 script_set_attribute(attribute:"solution", value:
"Disable access to port 445 by using a firewall. Additionally, apply
Microsoft MS04-011 patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/26");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
script_xref(name:"MSFT", value: "MS04-011");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "Look at ports 113 and 3067 (Korgo backdoor)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 #script_dependencies("find_service1.nasl");
 script_require_ports(113, 3067);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

paranoia = get_kb_item("global_settings/report_paranoia");
if ('Paranoia' >!< paranoia)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

#
# The script code starts here
#
ports =  make_list(3067, 113);

foreach p (ports)
{
 if (! get_port_state(p))
  exit(0);
}

foreach p (ports)
{
 s = open_sock_tcp(p);
 if (! s) exit(0);
 close(s);
}

security_hole(port: ports[0]);
