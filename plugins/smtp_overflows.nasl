#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11772);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_name(english:"SMTP Generic Overflow Detection");
  script_summary(english:"Tries overflows on SMTP commands arguments");

  script_set_attribute(attribute:'synopsis', value:"The remote SMTP server is vulnerable to a buffer overflow.");
  script_set_attribute(attribute:'description', value:
"The remote SMTP server crashes when it is sent a command with a too
long argument.

An attacker might use this flaw to kill this service or worse, execute
arbitrary code on the server.");
  script_set_attribute(attribute:'solution', value:
"This plugin tests for a generic condition. It may be remedied by
upgrading, reconfiguring, or changing the SMTP Server (MTA).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencie("sendmail_expn.nasl", "smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
banner = smtp_recv_banner(socket:soc);
if (!banner)
{
  close(soc);
  exit(0);
}

cmds = make_list(
	"HELO",
	"EHLO",
	"MAIL FROM:",
	"RCPT TO:",
	"ETRN");
args = make_list(
	"test.nessus.org",
	"test.nessus.org",
	strcat("test@", get_host_name()),
	strcat("test@[", get_host_ip(), "]"),
	"test.nessus.org");
n = max_index(cmds);

for (i = 0; i < n; i ++)
{
  ##display("cmd> ", cmds[i], "\n");
  send(socket: soc,
       data: strcat(cmds[i], " ",
                    str_replace(string: args[i],
                                find: "test",
                                replace: crap(4095)),
                    '\r\n'));
  repeat
  {
    data = recv_line(socket: soc, length: 32768);
    ##display("data>  ", data);
  }
  until (data !~ '^[0-9][0-9][0-9]-');
  # A Postfix bug: it answers with two codes on an overflow
  repeat
  {
    data2 = recv_line(socket: soc, length: 32768, timeout: 1);
    ##if (data2) display("data2> ", data2);
  }
  until (data2 !~ '^[0-9][0-9][0-9]-');

  if (! data)
  {
    close(soc);
    for (i = 0; i < 3; i ++)
    {
      sleep(i);
      soc = open_sock_tcp(port);
      if (soc) break;
    }
    if (! soc)
    {
      security_hole(port);
      exit(0);
    }
    for (j = 0; j <= i; j ++)
    {
      send(socket: soc, data: strcat(cmds[i], " ", args[i], '\r\n'));
      data = recv_line(socket: soc, length: 32768);
    }
  }
}

smtp_close(socket: soc);

