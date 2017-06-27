#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Broken link deleted


include("compat.inc");

if(description)
{
  script_id(10920);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/08/30 21:34:00 $");
 
  script_name(english:"RemotelyAnywhere WWW Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A web server is listening on the remote host.");
 script_set_attribute(attribute:"description", value:
"A RemotelyAnywhere WWW server is running on the remote host. According
to NAVCIRT, attackers use this management tool as a backdoor.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/isn/2002/Mar/102");
 script_set_attribute(attribute:"solution", value:
"If you installed the RemotelyAnywhere WWW server then you can ignore
this warning. If not, your machine is likely compromised by an
attacker." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/25");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:remotelyanywhere:remotelyanywhere");
 script_end_attributes();

  script_summary(english:"Detect RemotelyAnywhere www server");
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"Backdoors");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2000, 2001);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2000);
ports = add_port_in_list(list:ports, port:2001);

foreach port (ports)
{
 banner = get_http_banner(port:port);

 if (! banner) exit(0);

 if (egrep(pattern:"^Server: *RemotelyAnywhere", string:banner))
 {
  security_note(port);
 }
}
# TBD: check default account administrator / remotelyanywhere
