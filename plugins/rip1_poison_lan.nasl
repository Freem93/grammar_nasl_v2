#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(39588);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/03 18:01:48 $");

  script_name(english: "RIP-1 Poisoning Routing Table Modification");
  script_summary(english:"RIP-1 server detection");
 
  script_set_attribute(attribute:"synopsis", value:
"It may be possible to hijack connections on this network." );
  script_set_attribute(attribute:"description", value:
"This host is running a RIP-1 agent.

RIP-1 does not implement authentication.  An attacker on the same
network may feed the target machine bogus routes and hijack network
connections. 

Note that Nessus cannot test this flaw as it is not running on the
same network." );
  script_set_attribute(attribute:"solution", value: 
"Either disable the RIP agent if it is not used or use RIP-2 and
implement authentication." );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/07/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK); # Not an attack per se, but rip_poison is
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencie("rip_detect.nasl", "rip_poison.nasl", "rip_poison_lan.nasl");
  script_require_keys("Services/udp/rip");
  exit(0);
}

# poisoning on localnet is reliable so rip_poison_lan should report it
if (islocalnet()) exit(0);

port = get_kb_item("Services/udp/rip");
if (! port) port = 520;

if (! get_kb_item('rip/'+port+'/poison') && 
    get_kb_item("rip/" + port + "/version") == 1)
 security_warning(port: port, proto: "udp");
