#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42960);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-4118");
  script_bugtraq_id(37077);
  script_xref(name:"OSVDB", value:"60416");
  script_xref(name:"Secunia", value:"37419");

  script_name(english:"Cisco VPN Client on Windows Service Control Manager DoS");
  script_summary(english:"Local version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The VPN client installed on the remote Windows host has a local
denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the Cisco VPN client installed on the remote host
reportedly has a local denial of service vulnerability.  The
'StartServiceCtrlDispatcher' function of the 'cvpnd' service is
implemented improperly.  Attempting to run 'cvpnd.exe' from the
command line causes the service to stop.  A local attacker could
exploit this to tear down any active VPN sessions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.exploit-db.com/exploits/10190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=19445"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco VPN Client version 5.0.06.0100 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/19"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/19"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/01"
  );
 script_cvs_date("$Date: 2017/05/16 19:35:38 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vpn_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_vpn_client_detect.nasl");
  script_require_keys("SMB/CiscoVPNClient/Version");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/CiscoVPNClient/Version");
if (isnull(ver)) exit(1, "The 'SMB/CiscoVPNClient/Version' KB item is missing.");

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

fix_ver = '5.0.06.0100';
fix = split(fix_ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
{
  if ((iver[i] < fix[i]))
  {
    port = get_kb_item("SMB/transport");

    if (report_verbosity > 0)
    {
      report = '
Installed version : '+ver+'
Fixed version     : '+fix_ver;
      security_note(port:port, extra:report);
    }
    else security_note(port);

    exit(0);
  }
  else if (iver[i] > fix[i])
    break;
}
exit(0, 'The remote host is not affected since Cisco VPN Client version '+ver+' is installed.');

