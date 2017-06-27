#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34238);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english: "IRC Bouncer (BNC) Detection");
  script_summary(english: "Check if an IRC bouncer is running");

 script_set_attribute(attribute:"synopsis", value:
"An IRC bouncer is running on this port." );
 script_set_attribute(attribute:"description", value:
"An IRC bouncer (aka BNC) is running on this port.  It proxies
communications between IRC clients and servers.  This may be done to
allow clients without direct network access to connect to servers or
to hide client addresses. 

Legimate use of such proxies is rare.  They are often installed by
attackers in order to avoid detection while controlling a 'botnet'." );
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Bouncer_(networking)" );
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Botnet#Formation_and_exploitation" );
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software is in agreement with your
organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/17");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Service detection");
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl", "find_service2.nasl", "ezbounce_detect.nasl", "bnc_detect.nasl");
  script_require_ports("Services/irc-bnc");
  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/irc-bnc");
if (!port) exit(0);

if (get_port_state(port)) security_note(port);
