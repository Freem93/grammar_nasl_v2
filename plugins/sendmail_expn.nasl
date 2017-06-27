#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10249);
 script_version("$Revision: 1.58 $");
 script_cvs_date("$Date: 2014/09/23 20:41:30 $");

 script_osvdb_id(12551);

 script_name(english:"Multiple Mail Server EXPN/VRFY Information Disclosure");
 script_summary(english:"EXPN and VRFY checks");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate the names of valid users on the remote
host.");
 script_set_attribute(attribute:"description", value:
"The remote SMTP server answers to the EXPN and/or VRFY commands.

The EXPN command can be used to find the delivery address of mail
aliases, or even the full name of the recipients, and the VRFY command
may be used to check the validity of an account.

Your mailer should not allow remote users to use any of these
commands, because it gives them too much information.");
 script_set_attribute(attribute:"solution", value:
"If you are using Sendmail, add the option :

 O PrivacyOptions=goaway

in /etc/sendmail.cf.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'SMTP User Enumeration Utility');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1982/08/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 script_dependencies("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0, "The SMTP server listening on port "+port+" is broken.");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

b = smtp_recv_banner(socket:soc);
if (!b) audit(AUDIT_NO_BANNER, port);
trace = '\n  ' + chomp(b);

s = 'HELO example.com';
send(socket:soc, data:s+'\r\n');
r = smtp_recv_line(socket:soc);
trace += '\n  ' + s +
         '\n  ' + chomp(r);

vuln = 0;

s = 'EXPN root';
send(socket:soc, data:s+'\r\n');
expn_root = r = smtp_recv_line(socket:soc);
trace_expn = '\n  ' + s +
             '\n  ' + chomp(r);

# Some Postfix reply as follow:
#
# 220-localhost.localhost ESMTP Postfix
# HELO there
# 220 localhost.localhost ESMTP Postfix
# 250 localhost.localhost
# EXPN root
# 502 5.5.2 Error: command not recognized
#
if ( r =~ "^250 " )
{
  r2 = smtp_recv_line(socket:soc);
  if (r2)
  {
    expn_root = r = r2;
    trace_expn += '\n  ' + chomp(r2);
  }
}

if (
  ereg(string:r, pattern:"^(250|550)(-| ).*$") &&
  # exim hack
  !ereg(string:r, pattern:"^550 EXPN not available.*$") &&
  !ereg(string:r, pattern:"^550.*Administrative prohibition.*$") &&
  !ereg(string:r, pattern:"^550.*Access denied.*$") &&
  # QHMail 4.6.3.1
  !ereg(string:r, pattern:"^550 lists are confidential.*$") &&
  # PMDF MTA
  !ereg(string:r, pattern:"^550.* EXPN command has been disabled\.$") &&
  !ereg(string:r, pattern:"^550.*EXPN")
)
{
  # nb: check for a bogus account to avoid false positives; eg,
  #     Postfix with EXPN in 'smtpd_noop_commands'.
  if (report_paranoia < 2)
  {
    s2 = 'EXPN random' + rand();
    send(socket:soc, data:s2+'\r\n');
    r2 = smtp_recv_line(socket:soc);

    trace_expn += '\n  ' + s2 +
                  '\n  ' + chomp(r2);
  }
  else r2 = s2 = NULL;

  if (
    isnull(s2) ||
    (
      ereg(string:r2, pattern:"^(250|550)(-| ).*$") &&
      substr(expn_root, 0, 2) != substr(r2, 0, 2)
    )
  )
  {
    trace += trace_expn;

    set_kb_item(name:"SMTP/expn", value:TRUE);
    vuln++;
  }
}

s = 'VRFY root';
send(socket:soc, data:s+'\r\n');
vrfy_root = r = smtp_recv_line(socket:soc);
trace_vrfy = '\n  ' + s +
             '\n  ' + chomp(r);

if (ereg(string:r, pattern:"^(250|550)(-| ).*$"))
{
  if (report_paranoia < 2)
  {
    s2 = 'VRFY random' + rand();
    send(socket:soc, data:s2+'\r\n');
    r2 = smtp_recv_line(socket:soc);

    trace_vrfy += '\n  ' + s2 +
                  '\n  ' + chomp(r2);
  }
  else r2 = s2 = NULL;

  if (
    isnull(s2) ||
    (
      ereg(string:r2, pattern:"^(250|550)(-| ).*$") &&
      substr(vrfy_root, 0, 2) != substr(r2, 0, 2)
    )
  )
  {
    trace += trace_vrfy;

    set_kb_item(name:"SMTP/vrfy", value:TRUE);
    vuln++;
  }
}
smtp_close(socket:soc);


if (vuln > 0)
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Here is a trace of the SMTP traffic that demonstrates the issue';
    if (vuln > 1) report += 's';
    report += ' : ' +
              '\n' + trace +
              '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The SMTP server listening on port "+port+" is not affected.");
