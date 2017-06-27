#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11090);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_osvdb_id(50518);

 script_name(english:"AppSocket Half-open Connection Remote DoS");
 script_summary(english:"Too many Appsocket connections");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It seems that it is possible to lock out your printer from the network
by opening a few connections and keeping them open.

** Note that the AppSocket protocol is so crude that Nessus ** cannot
check if it is really running behind this port.");
 script_set_attribute(attribute:"solution", value:"Change your settings or firewall your printer");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(35, 2501, 9100);
 exit(0);
}


include("audit.inc");
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
function test_app_socket(port)
{
  local_var i, j, s, soc;

  #display("Testing port ", port, "\n");
  if (! get_port_state(port)) return(0);

  soc = open_sock_tcp(port);
  if (! soc) return(0);

  # Don't close...
  s[0] = soc;

  for (i = 1; i < 16; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_warning(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
      return(1);
    }
    sleep(1);	# Make inetd (& others) happy!
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
  return (0);
}

test_app_socket(port: 35);
test_app_socket(port: 2501);
test_app_socket(port: 9100);

