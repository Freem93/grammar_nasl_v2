#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35309);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"CA Unicenter Cron Scheduler Detection");
  script_summary(english:"Sends a status command");

 script_set_attribute(attribute:"synopsis", value:
"A scheduling service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a Cron Scheduler for CA Unicenter applications, 
that is used to launch programs at specified times." );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/products/product.aspx?id=4574" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 6674);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(6674);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 6674;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner looks like smmCron.
if (report_paranoia < 2 && !COMMAND_LINE)
{
  banner = get_unknown_banner(port:port, dontfetch:TRUE);
  if (!banner || 'Unknown request "' >!< banner) exit(0);
}


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a 'status' command.
req = 'status';
send(socket:soc, data:req+'\n');
res = recv(socket:soc, length:256, min:128);
close(soc);
if (res == NULL) exit(0);


# If it looks like a valid reply from smmCron...
if (
  "Unicenter" >< res &&
  "Cron Scheduler" >< res
)
{
  # Register and report the service.
  register_service(port:port, proto:"unicenter_smmcron");

  info = "";
  if (report_verbosity > 1)
  {
    # Collect a list of jobs.
    soc = open_sock_tcp(port);
    if (soc)
    {
      req = 'list';
      send(socket:soc, data:req+'\n');
      res = recv(socket:soc, length:4096);
      close(soc);

      if ("command list" >< tolower(res))
      {
        foreach line (split(res, keep:FALSE))
          if (stridx(line, "- ") >= 0) info += '  ' + line + '\n';
        if (info) info = string(
          "The following tasks are in the remote scheduler's queue :\n",
          "\n",
          info
        );
      }
    }
  }

  if (info) security_note(port:port, extra:'\n'+info);
  else security_note(port);
}
