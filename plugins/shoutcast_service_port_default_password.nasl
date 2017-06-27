#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31098);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Default Password (changeme) for SHOUTcast Server Service Port");
  script_summary(english:"Tries to log into SHOUTcast Server with default password");

  script_set_attribute(attribute:"synopsis", value:"The remote service is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote SHOUTcast Server's service port is configured to use the
default password to allow broadcasting content and administration. 
Knowing it, an attacker can gain administrative control of the affected
application.");
  script_set_attribute(attribute:"solution", value:
"Edit the application's 'sc_serv.ini' file and change the 'Password'
setting.  Then, restart the service to put the change into effect.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:shoutcast_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/shoutcast_service", 8001);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/shoutcast_service");
if (!port) port = 8001;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to authenticate.
pass = "changeme";

send(socket:soc, data:pass+'\r\n');
res = recv(socket:soc, length:256, min:14);
close(soc);


# If the response looks right...
if (
  strlen(res) &&
  'OK2\r\nicy-caps:' >< res
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the password "' + pass+ '"\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, 'affected');
