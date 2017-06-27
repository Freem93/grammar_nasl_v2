#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38929);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-6273");
  script_bugtraq_id(26689);
  script_xref(name:"OSVDB", value:"42502");
  script_xref(name:"Secunia", value:"27917");

  script_name(english:"SonicWALL Global VPN Client < 4.0.0.830 Format String Vulnerabilities");
  script_summary(english:"Checks client's version number");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote Windows host contains a program that is affected by multiple
format string vulnerabilities."  );
  script_set_attribute(  attribute:"description",   value:
"The version of the SonicWALL Global VPN Client software installed on
the remote Windows host fails to sanitize the 'name' attribute of the
'Connection' tag and the content of the 'Hostname' tag in the
configuration file of format strings.  If an attacker can trick a user
on the affected host into importing a specially crafted configuration
file, the attacker could leverage this issue to execute arbitrary code 
on the affected host subject to the user's privileges."  );
   # https://www.sec-consult.com/files/20071204-0-sonicwall-globalVPN-fmtstring.txt
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?a0715256"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2007/Dec/21"
  );
  script_set_attribute(  attribute:"solution",  value:
"Upgrade to SonicWALL VPN client 4.0.0.830 as that reportedly resolves
the issue."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(134);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/27");
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:sonicwall:global_vpn_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("sonicwall_vpn_client_detect.nasl");
  script_require_keys("SMB/SonicWallGlobalVPNClient/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/SonicWallGlobalVPNClient/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 4 ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] == 0 && ver[3] < 830)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "SonicWALL Global VPN Client version ", version, " is currently installed on\n",
      "the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
