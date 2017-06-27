#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(11483);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2011/07/02 19:33:54 $");
 
  script_name(english:"apcnisd / apcupsd Detection");
  script_summary(english:"Sends a status message");
 
  script_set_attribute(attribute:"synopsis", value:
"A UPS monitoring service is listening on the remote port." );
  script_set_attribute(attribute:"description", value:
"The remote service is a daemon to monitor and manage an APC UPS
battery backup unit." );
  script_set_attribute(attribute:"solution", value:
"Access to this port should be restricted to authorized hosts only, as
a flaw or a lack of authentication in this service may allow an
attacker to turn off the devices plugged into the remote APC." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown", 3551, 7000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if ( thorough_tests && !get_kb_item("global_settings/disable_service_discovery") )
{
 ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:7000);
}
else ports = make_list(7000);
ports = add_port_in_list(list:ports, port:3551);

# Loop through each port.
foreach port (ports)
{
  if (service_is_unknown(port:port) && get_tcp_port_state(port))
  {
    soc = open_sock_tcp(port);
    if (soc)
    {
      # Send a status request.
      req = raw_string(0x00, 0x06) + "status";
      send(socket:soc, data:req);

      res = recv(socket:soc, length:4096);
      if ("APC" >< res && "MODEL" >< res)
      {
        register_service(port:port, proto:"apcnisd");

        if (report_verbosity)
        {
          report = '\n' +
                   'Here is the status of the remote APC UPS :\n' +
                   '\n';
          foreach line (split(res, keep:FALSE))
            report += '  ' + substr(line, 2) + '\n';
          security_note(port:port, extra:report);
        }
        else security_note(port);
      }
      close(soc);
    }
  }
}
