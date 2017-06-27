#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70212);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_name(english:"Alcatel OmniSwitch Default Credentials (telnet)");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote device can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Alcatel OmniSwitch by providing
the default credentials.  A remote attacker could exploit this to gain
administrative control of the remote device.");
  script_set_attribute(attribute:"solution", value:"Change the default password or block access to the port.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:alcatel-lucent:omniswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alcatel:aos");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("telnet.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("telnet_func.inc");

# The default telnet credentials
default_username = 'admin';
default_password = 'switch';

port = 23;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

s = open_sock_tcp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port);

# The connections start with a newline
send(socket:s, data:'\r\n');
data = recv(socket:s, length:4096);


# Note: '><' and '=~' don't work here (probably because of non-ascii in the string)
if ( "login : " >!< data ) exit(0, "Unrecognized device.");

send(socket:s, data:default_username + '\r\n');
data = recv(socket:s, length:4096);

send(socket:s, data:default_password + '\r\n');
banner = data = recv(socket:s, length:4096);

if ("Welcome to the Alcatel-Lucent OmniSwitch" >< data)
{
  send(socket:s, data:'exit\r\n');
  if (report_verbosity > 0)
  {
    report = '\n' +
            'Nessus uncovered the following set of default credentials :\n' +
            '\n' +
            default_username + ' / ' + default_password + '\n' +
            '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_RESP_BAD, port);
