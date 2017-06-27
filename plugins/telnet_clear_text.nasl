#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42263);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");

 script_name(english:"Unencrypted Telnet Server");
 script_summary(english:"Checks if the telnet service is unencrypted.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Telnet server transmits traffic in cleartext.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a Telnet server over an unencrypted
channel.

Using Telnet over an unencrypted channel is not recommended as logins,
passwords, and commands are transferred in cleartext. This allows a 
remote, man-in-the-middle attacker to eavesdrop on a Telnet session to
obtain credentials or other sensitive information and to modify
traffic exchanged between a client and server.

SSH is preferred over Telnet since it protects credentials from
eavesdropping and can tunnel additional data streams such as an X11
session.");
 script_set_attribute(attribute:"solution", value:
"Disable the Telnet service and use SSH instead.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("telnetserver_detect_type_nd_version.nasl", "telnet_starttls.nasl");
 script_require_ports("Services/telnet", 23);

 exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("telnet2_func.inc");

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

trp = get_port_transport(port);
if (trp > ENCAPS_IP) exit(0, "The Telnet service listening on port "+port+" encrypts traffic.");

global_var banner, sb;
global_var then;

function get_telnet_banner(port)
{
  sb = "Services/telnet/banner/"+port;
  banner = get_kb_item(sb);
  if (banner) return(banner);

  if (!telnet2_init(port:port, timeout:3 * get_read_timeout())) return NULL;
  then = unixtime();
  banner = NULL;
  telnet_loop();
  return banner;
}

function telnet_callback()
{
  local_var str;
  local_var sbanner;

  str = _FCT_ANON_ARGS[0];
  if ( str != NULL ) banner += str;
  else if (
    unixtime() > then + get_read_timeout() ||
    "ogin:" >< banner ||
    "word:" >< banner ||
    strlen(banner) > 512
  )
  {
    if ( banner && egrep(pattern:"[Ll]ogin:", string:banner) )
    {
      sbanner = str_replace(find:raw_string(0), replace:'', string:banner);
      if ( strlen(sbanner) ) replace_kb_item(name: sb, value:sbanner);
    }
    return -1;
  }
  return 0;
}

banner = get_telnet_banner(port:port);
if (
  strlen(banner) &&
  "Encryption is required. Access is denied." >!< banner &&
  'a TLS/SSL enabled telnet client MUST be used to connect' >!< banner
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus collected the following banner from the remote Telnet server :' +
      '\n' +
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
      '\n' + banner +
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    if (get_kb_item('telnet/'+port+'/starttls'))
      report +=
        '\n' + 'Note that it was not necessary to use the Telnet START_TLS option to' +
        '\n' + 'obtain this banner; however, the service does support this option.\n';

    if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
    security_warning(port:port, extra:report);
  }
  else
  {
    if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port,
						value:"The remote Telnet server transmits traffic in cleartext.");
    security_warning(port);
  }
  exit(0);
}
else exit(0, "Failed to negotiate a connection with the Telnet service listening on port "+port+" without using START_TLS.");
