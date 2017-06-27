#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52482);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"EA Need For Speed Underground Detection");
  script_summary(english:"Reports EA Need For Speed Underground client relay");

  script_set_attribute(attribute:"synopsis", value:"A game server has been detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a client relay service for Electronic Arts
Need For Speed Underground or a clone of that game.

This is a kind of port mapper in that the service provides dynamic
port numbers to client software.");
  script_set_attribute(attribute:"see_also", value:"http://www.nfsplanet.de/en");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Need_for_speed_underground");
  script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/nfsu-relay", 10800);

  exit(0);
}


include("global_settings.inc");
include('misc_func.inc');

port = get_service(svc: "nfsu-relay", default: 10800, exit_on_fail: 1);

if (service_is_unknown(port: port))
{
  if (silent_service(port)) exit(0, "The service on port "+port+" is 'silent'.");
  b = get_unknown_banner(port: port);
  if (ereg(string: b, pattern: "^[0-9]+\|[0-9]+\|[1-6]?[0-9][0-9][0-9][0-9]\|[^|]+|[0-9.]+\|[^|]+$"))
    register_service(port: port, proto: 'nfsu-relay');
  else
    exit(0, "The service on port "+port+" is not an NFSU relay.");
}
else if (! verify_service(port: port, proto: "nfsu-relay"))
  exit(0, "The service on port "+port+" is not an NFSU relay.");

security_note(port: port);
