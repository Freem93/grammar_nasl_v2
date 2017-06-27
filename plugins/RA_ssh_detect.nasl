#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Broken link deleted


include("compat.inc");

if(description)
{
  script_id(10921);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2011/03/16 13:37:58 $");
 
  script_name(english:"RemotelyAnywhere SSH Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A SSH server is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The RemotelyAnywhere SSH server is running on this system. According 
to NAVCIRT, attackers target this management tool." );
 script_set_attribute(attribute:"see_also", value:"http://www.infosecnews.org/hypermail/0203/5628.html" );
 script_set_attribute(attribute:"solution", value:
"If you installed it, ignore this warning. If not, 
your machine is likely compromised by an attacker." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/25");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_summary(english:"Detect RemotelyAnywhere SSH server");
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
  script_family(english:"Backdoors");
  script_dependencie("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22); 
  exit(0);
}

port = get_kb_item("Services/ssh");
if (! port) port = 22;

if(!get_port_state(port))exit(0);


banner = get_kb_item("SSH/banner/" + port);
if (! banner) exit(0);

if (ereg(pattern:'SSH-[0-9.-]+[ \t]+RemotelyAnywhere', string:banner))
{
  security_note(port);
}

# TBD: check default account administrator / remotelyanywhere
