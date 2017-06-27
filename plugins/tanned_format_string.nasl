#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "dong-h0un yoU" <xploit@hackermail.com>
# To: vulnwatch@vulnwatch.org
# Date: Tue, 07 Jan 2003 16:59:11 +0800
# Subject: [VulnWatch] [INetCop Security Advisory] Remote format string vulnerability in
#    Tanne.

include("compat.inc");

if (description)
{
 script_id(11495);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");

 script_cve_id("CVE-2003-1236");
 script_bugtraq_id(6553);
 script_osvdb_id(56913);

 script_name(english:"Tanne netzio.c logger Function Remote Format String");
 script_summary(english:"Sends a format string to the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote service is affected by a format string vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote tanned server contains a format string vulnerability. An
attacker may use this flaw to gain a shell on this host.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q1/12");
 script_set_attribute(attribute:"solution", value:"Upgrade to tanned 0.7.1 or disable this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/28");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_require_keys("Settings/ParanoidReport");
 script_require_ports(14002, "Services/tanned");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("Services/tanned");
if(!port)port = 14002;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:string("%d%d%d%d\r\n"));
r = recv_line(socket:soc, length:4096);
if("|F|" >< r)
{
  close(soc);
  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  send(socket:soc, data:string("%n%n%n%n\r\n"));
  r = recv_line(socket:soc, length:4096);
  if(!r)security_hole(port);
}
