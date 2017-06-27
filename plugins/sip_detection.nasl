# Ferdy Riphagen and Josh Zlatin-Amishav
# GPLv2

# Changes by Tenable
#
# - Updated to use compat.inc (11/18/2009)
# - Updated to allow detection of Certified Asterisk (06/01/2012)
# - Updated to allow detection of TCP & TLS/TCP SIP Services (11/16/2012)
# - Small revision to the solution and fix exit call (09/18/2013)

include("compat.inc");

if (description) {
  script_id(21642);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2013/09/23 15:16:31 $");

  script_name(english:"Session Initiation Protocol Detection");
  script_summary(english:"Checks if the remote system understands the SIP protocol");

  script_set_attribute(attribute:"synopsis", value:"The remote system is a SIP signaling device.");
  script_set_attribute(attribute:"description", value:
"The remote system is running software that speaks the Session
Initiation Protocol (SIP).

SIP is a messaging protocol to initiate communication sessions between
systems.  It is a protocol used mostly in IP Telephony networks /
systems to setup, control, and teardown sessions between two or more
systems.");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Session_Initiation_Protocol");
  script_set_attribute(attribute:"solution", value:
"If possible, filter incoming connections to the port so that it is
used only by trusted sources.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Ferdy Riphagen and Josh Zlatin-Amishav");

  script_dependencies("find_service1.nasl", "find_service2.nasl");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

sip_listen = FALSE;

# default port list
port_list = make_list(5060, 5061, 5070);

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery"))
{
  additional_ports = get_kb_list("Services/unknown");
  if (!isnull(additional_ports))
    port_list = make_list(port_list, additional_ports);

  # Try even harder
  udp_ports = get_kb_list("Ports/udp/*");
  if (!isnull(udp_ports) && get_kb_item("Host/scanners/nessus_udp_scanner"))
  {
    foreach udpport (keys(udp_ports))
    {
      udpport = udpport - "Ports/udp/";
      port_list = make_list(port_list, udpport);
    }
  }
}

port_list = list_uniq(port_list);

foreach port (port_list)
{
  foreach protocol (make_list('udp', 'tcp'))
  {
    if (!service_is_unknown(port: port, ipproto:protocol))
    {
      if (get_kb_item("Known/" + protocol + "/" + port) != "sip")
        continue;
    }

    if (protocol == 'udp')
    {
      if (!get_udp_port_state(port)) continue;
      # Check if we are scanning our local system.
      # If so we can't use source port 5060, but it is worth a try.
      if (islocalhost()) {
       soc = open_sock_udp(port);
      }
      # Some systems (such as the Cisco 7905G IP Phone) only want to talk if
      # the source port is 5060.
      else soc = open_priv_sock_udp(sport:5060, dport:port);
    }
    else
    {
      if (!get_tcp_port_state(port)) continue;
      soc = open_sock_tcp(port);
    }

    if (!soc) continue;

    via_protocol = protocol;

    encaps = get_port_transport(port);
    if (!isnull(encaps) && protocol == 'tcp')
    {
      if (encaps && encaps > ENCAPS_IP)
        via_protocol = 'tls';
    }

    # Generate the 'SIP' OPTIONS packet
    query =  "OPTIONS sip:" + get_host_name() + " SIP/2.0" + '\r\n' +
             "Via: SIP/2.0/" + toupper(via_protocol) + " " + this_host() + ":" + port + '\r\n' +
             "Max-Forwards: 70" + '\r\n' +
             "To: <sip:" + this_host() + ":" + port + ">" + '\r\n' +
             "From: Nessus <sip:" + this_host() + ":" + port + ">;tag=" + rand() + '\r\n' +
             "Call-ID: " + rand() + '\r\n' +
             "CSeq: 63104 OPTIONS" + '\r\n' +
             "Contact: <sip:" + this_host() + ">" + '\r\n' +
             "Accept: application/sdp" + '\r\n' +
             "Content-Length: 0" + '\r\n\r\n';

    send(socket:soc, data:query);
    res = recv(socket:soc, length:1024);
    close(soc);

    if (!isnull(res))
    {
      # If it looks like a SIP packet
      if ( ("SIP/2.0/" + toupper(via_protocol)) >< res)
      {
        sip_listen = TRUE;
        banner = "";
        options = NULL;

        # Try to get details
        if ("Server:" >< res)
        {
          line = egrep(pattern:'^Server:', string: res);
          match = eregmatch(pattern:"^Server:[ \t]*(.+)", string:line);
          if (!isnull(match)) banner = match[1];
        }
        else if ("User-Agent:" >< res )
        {
          # Note: some servers don't send a Server response header but instead
          #       put the server name in the User-Agent header
          line = egrep(pattern:'^User-Agent:', string: res);
          match = eregmatch(pattern:"^User-Agent:[ \t]*(.+)", string:line);
          if (!isnull(match)) banner = match[1];
        }

        # Also try to report the remote capabilities.
        if (egrep(pattern:"^Allow:.+OPTIONS", string:res))
        {
          options = egrep(pattern:"^Allow:.+OPTIONS", string:res);
          if (options) options = options - "Allow: ";
        }

        if (strlen(banner) > 0)
        {
          banner = chomp(banner);
          report = '\nThe remote service was identified as :\n\n  ' + banner + '\n';

          if (protocol == 'tcp')
            set_kb_item(name:"sip/banner/" + port, value:banner);
          else
            set_kb_item(name:"sip/banner/" + protocol + "/" + port, value:banner);
        }
        else
        {
           report = '\nNessus found an unidentified SIP service.\n';
           if (protocol == 'tcp')
            set_kb_item(name:"sip/unknown_banner/" + port, value:TRUE);
           else
            set_kb_item(name:"sip/unknown_banner/" + protocol + "/" + port, value:TRUE);
        }

        if (strlen(options) && !isnull(options))
        {
          report = report +
                  '\nIt supports the following options :\n\n  ' + options;
        }
        register_service(ipproto:protocol, proto:"sip", port:port);
        security_note(port:port, protocol:protocol, extra:report);
      }
    }
  }
}

if (sip_listen) exit(0);

exit(0, "Nessus did not detect any remote SIP services.");
