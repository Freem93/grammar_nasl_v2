#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25906);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-4414");
  script_bugtraq_id(25332);
  script_osvdb_id(46723);
  script_xref(name:"IAVA", value:"2009-A-0106");

  script_name(english:"Cisco VPN Client on Windows Dial-up Networking Dialog Local Privilege Escalation");
  script_summary(english:"Checks version of vpngui.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is prone to a local
privilege escalation attack." );
 script_set_attribute(attribute:"description", value:
"The version of the Cisco VPN client installed on the remote host
reportedly allows an unprivileged local user to elevate his privileges
to the LocalSystem account by enabling the 'Start Before Login'
feature and configuring a VPN profile to use Microsoft's Dial-Up
Networking interface." );
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070815-vpnclient
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?132892db" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/476651/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco VPN Client version 4.8.02.0010 or later." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/08/15");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vpn_client");
script_set_attribute(attribute:"stig_severity", value:"I");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_vpn_client_detect.nasl");
  script_require_keys("SMB/CiscoVPNClient/Version");

  exit(0);
}


ver = get_kb_item("SMB/CiscoVPNClient/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<4; i++)
  iver[i] = int(iver[i]);

fix = split("4.8.02.0010", sep:'.', keep:FALSE);
for (i=0; i<4; i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
  if ((iver[i] < fix[i]))
  {
    security_warning(get_kb_item("SMB/transport"));
    break;
  }
  else if (iver[i] > fix[i])
    break;
