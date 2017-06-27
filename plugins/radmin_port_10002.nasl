#
# (C) Tenable Network Security, Inc.
#

# Based on radmin_detect.nasl, by Michel Arboi
#


include("compat.inc");

if(description)
{
  script_id(14834);
  script_version ("$Revision: 1.20 $");
  script_cve_id("CVE-2004-0200");
  script_osvdb_id(9951);
 
  script_name(english:"Radmin (Remote Administrator) Port 10002 - Possible GDI Compromise");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may have been compromised" );
 script_set_attribute(attribute:"description", value:
"The remote host is running radmin - a remote administration tool - on
port 10002. 

This indicates that an attacker may have exploited one of the flaws
described in MS04-028 with a widely available exploit. 

As a result, anyone may connect to the remote host and gain 
control by logging into the remote radmin server." );
 script_set_attribute(attribute:"see_also", value:"http://www.freerepublic.com/focus/f-news/1229010/posts" );
 script_set_attribute(attribute:"solution", value:
"Re-install the operating system, as it has likely been compromised." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/14");
 script_cvs_date("$Date: 2016/04/29 19:06:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
  script_summary(english:"Detect radmin");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Backdoors");
  script_require_ports(10002);
  exit(0);
}

#

port = 10002;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = raw_string(0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x08);
send(socket: soc, data: req);
r = recv(socket: soc, length: 6);
close(soc);
xp1 = "010000002500";
xp2 = "010000002501";


if (( xp1 >< hexstr(r) ) || ( xp2 >< hexstr(r) ))
{
        security_hole(port);
	exit(0);
}
