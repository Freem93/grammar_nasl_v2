#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(39589);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_name(english: "RIP-2 Poisoning Routing Table Modification");
  script_summary(english:"RIP-2 server detection");
 
  script_set_attribute(attribute:"synopsis", value:
"It might be possible to hijack connections on this network." );
  script_set_attribute(attribute:"description", value:
"This host is running a RIP-2 agent.

RIP-2 requests can be authenticated but Nessus cannot check this in
the current configuration. 

If authentication is not implemented, an attacker on the same network
may feed the target machine bogus routes and hijack network
connections. 

Note that this may be a false positive." );
  script_set_attribute(attribute:"solution", value: 
"Either disable the RIP agent if it is not used or implement RIP-2
authentication." );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/07/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK); # Not an attack per se, but rip_poison is
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencie("rip_detect.nasl", "rip_poison.nasl", "rip_poison_lan.nasl");
  script_require_keys("Services/udp/rip");
  exit(0);
}

include("global_settings.inc");

if (report_paranoia < 1) exit(0);
# poisoning on localnet is reliable so rip_poison_lan should report it
if (islocalnet()) exit(0);

port = get_kb_item("Services/udp/rip");
if (! port) port = 520;

if (! get_kb_item('rip/'+port+'/poison') && 
    get_kb_item("rip/" + port + "/version") == 2)
 security_warning(port: port, proto: "udp");
