#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52481);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/17 14:47:25 $");

  script_name(english:"Aeonian Dreams Detection");
  script_summary(english:"Reports Aeonian Dreams game server");

  script_set_attribute(attribute:"synopsis", value:"A game server has been detected on the remote host.");
  script_set_attribute(attribute:"description", value:"The remote host is running an 'Aeonian Dreams' game server.");
  # http://web.archive.org/web/20101116044248/http://wiki.aeonian-dreams.net/index.php/Main_Page
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e70fb3ce");
  script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/aeonian-dreams", 4000);

  exit(0);
}


include("global_settings.inc");
include('misc_func.inc');

port = get_service(svc: "aeonian-dreams", default: 4000, exit_on_fail: 1);

if (service_is_unknown(port: port))
{
  if (silent_service(port)) exit(0, "The service on port "+port+" is 'silent'.");
  b = get_unknown_banner(port: port);
  if ("A E O N I A N   D R E A M S" >< b &&
      "R E A W A K E N E D" >< b )
    register_service(port: port, proto: 'aeonian-dreams');
  else
    exit(0, "The service on port "+port+" is not an Aeonian Dreams server.");
}
else if (! verify_service(port: port, proto: "aeonian-dreams"))
  exit(0, "The service on port "+port+" is not an Aeonian Dreams server.");

security_note(port: port);
