#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10284);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");

 script_cve_id("CVE-1999-1516");
 script_osvdb_id(224);
 
 script_name(english:"TFS SMTP 3.2 MAIL FROM overflow");
 script_summary(english:"Overflows a buffer in the remote mail server"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server may be affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote SMTP server may be affected by a buffer overflow triggered
when it receives an overly long argument to the 'MAIL FROM' command. 

This vulnerability is reported to affect TenFour TFS SMTP and may
allow an unauthenticated remote attacker to crash the service or even
execute arbitrary code on this system.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Sep/105");
 script_set_attribute(attribute:"solution", value:"Upgrade to TenFour TFS SMTP 4.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value:"1999/09/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail:TRUE);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0, "The SMTP server listening on port "+port+" is broken.");

if (get_kb_item("SMTP/"+port+"/postfix")) exit(0, "The SMTP server listening on port "+port+" is Postfix, not TenFour TFS SMTP.");
if (get_kb_item("SMTP/"+port+"/qmail")) exit(0, "The SMTP server listening on port "+port+" is qmail, not TenFour TFS SMTP.");


banner = get_smtp_banner(port:port);
if (report_paranoia < 2 || safe_checks())
{
  if (isnull(banner)) exit(1, "Failed to retrieve the banner from the SMTP server listening on port "+port+".");
  if ("TFS SMTP Server" >!< banner) exit(1, "The banner from the SMTP server listening on port "+port+" is not from TenFour TFS SMTP.");
}


if (safe_checks())
{
  item = eregmatch(pattern:"TFS SMTP Server( ver)? ([0-9]+\.[0-9.]+)", string:banner);
  if (!isnull(item)) exit(1, "Failed to extract the version from banner from the SMTP server listening on port "+port+".");
  version = item[2];

  if (version =~ "^[1-3]\.")
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n  Version source     : ' + banner +
        '\n  Installed version  : ' + version +
        '\n  Fixed version      : 4.0' +
        '\n' +
        '\n' + 'Note that Nessus only checked the version in the banner because safe' +
        '\n' + 'checks were enabled for this scan.\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_LISTEN_NOT_VULN, "TenFour TFS SMTP", port, version);
}
else
{
  # unsafe check
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_PORT_CLOSED, port);

  data = smtp_recv_banner(socket:soc);	
  trace = strcat('S : ', data);

  crp = 'HELO example.com\r\n';
  send(socket:soc, data:crp);
  trace = strcat(trace, 'C : ', crp);

  data = recv_line(socket:soc, length:1024);
  if ("250 " >< data)
  {
    trace = strcat('S : ', data);

    crp = 'MAIL FROM: ' + crap(1024) + '\r\n';
    send(socket:soc, data:crp);
    trace = strcat(trace, 'C : ', crp);

    buf = recv_line(socket:soc, length:1024);
    if (!buf)
    {
      close(soc);
      for (i = 0; i < 3; i ++)
      {
        sleep(i);
        soc2 = open_sock_tcp(port);
        if (soc2) break;
      }
      if (soc2)
      {
        s = smtp_recv_banner(socket:soc2);
        close(soc2);
      }
      else s = NULL;

      if (!s)
      {
        if (report_verbosity > 0)
        {
          trace = '\n  ' + str_replace(find:'\n', replace:'\n  ', string:trace);
          trace = chomp(trace);

          report = strcat(
            '\nHere is a trace of the traffic that demonstrates the issue :',
            '\n',
            trace
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);

        set_kb_item(name:string("SMTP/", port, "/mail_from_overflow"), value:TRUE);
      }
    }
  }
  close(soc);
}
