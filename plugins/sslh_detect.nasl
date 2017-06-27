#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42476);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/09/14 19:48:34 $");

  script_name(english:"sslh Detection");
  script_summary(english:"Detects sslh");

  script_set_attribute(attribute:"synopsis", value:
"A multiplexing service may be running on this port.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running an sslh daemon.  sslh is a
multiplexing service that can accept SSH or SSL connections on the
same port, such as 443 from inside a corporate firewall.");
  script_set_attribute(attribute:"see_also", value:"http://www.rutschle.net/tech/sslh.shtml");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this service agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if ( ! thorough_tests ) exit(0);
ports_l = get_kb_list("Transport/SSL");

foreach port(ports_l)
{
  s = open_sock_tcp(port, transport: ENCAPS_IP);
  if (s)
  {
    t1 = unixtime();
    r = recv_line(socket: s, length: 64, timeout: get_read_timeout() + 3);
    t2 = unixtime();
    if (r =~ "^SSH-")
    {
      register_service(port: port, proto: "sslh");
      security_note(port:port, extra: strcat(
"\nThis service is supposed to run on top of SSL / TLS, but it returned
an SSH banner over an unencrypted channel after ", t2 - t1, " seconds."));
    }
    close(s);
  }
}

ports_l = get_kb_list("Services/ssh");

# If this is a real SSH server, SSL connections will fail at once and
# this script won't be slow
encaps_l = make_list(ENCAPS_SSLv23, ENCAPS_TLSv1, ENCAPS_SSLv3, ENCAPS_SSLv2);
  
foreach port(ports_l)
{
  t = get_port_transport(port);
  if (t > ENCAPS_IP) continue;	# SSH on SSL/TLS

  foreach t (encaps_l)
  {
    s = open_sock_tcp(port, transport: t);
    if (s)
    {
      register_service(port: port, proto: "sslh");
      security_note(port:port, extra: 
"\nThis service was identified as an SSH daemon, but it was possible to
connect to it through SSL / TLS.");
      close(s);
      break;
    }
  }
}
