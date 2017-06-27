#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57914);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2013/02/17 01:24:57 $");

  script_name(english:"Service Detection : SMTP Server on a Well-Known Port");
  script_summary(english:"Identifies SMTP servers on default ports");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service could be identified."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This plugin attempts to collect the banner from services listening on
well-known SMTP ports.  It is not expected to report anything."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_require_ports(25, 587);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


found = FALSE;
max_delay = 35;
ports = make_list(25, 587);

banner = make_array();
soc = make_array();

open_socs = 0;
foreach port (ports)
{
  if ( get_kb_item("Ports/tcp/"+port))
  {
    soc[port] = open_sock_tcp(port);
    if (soc[port]) open_socs++;
  }
}

deadline = unixtime() + max_delay;
then = unixtime();
while (open_socs > 0 && unixtime() < deadline)
{
  flag = 0;
  open_socs = 0;
  foreach port (ports)
  {
    if (soc[port] <= 0) continue;

    if (socket_pending(soc[port]) > 0 )
    {
      banner = smtp_recv_banner(socket:soc[port]);
      if (banner) replace_kb_item(name:"Banner/"+port, value:banner);

      greetpause = (unixtime() - then) + 10;
      set_kb_item(name:"smtp/"+port+"/greetpause", value:greetpause);

      close(soc[port]);
      soc[port] = -1;
      flag = 1;
      found = TRUE;
    }
    else open_socs++;
  }
  if (flag && open_socs > 0) usleep(50000);
}

if (!found) exit(0, "No SMTP server was found on ports "+join(sep:" & ", ports)+".");
