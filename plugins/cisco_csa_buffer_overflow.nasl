#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32131);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2007-5580");
  script_bugtraq_id(26723);
  script_osvdb_id(39521);

  script_name(english:"Cisco Security Agent for Microsoft Windows Crafted SMB Packet Remote Overflow");
  script_summary(english:"Checks Cisco Security Agent version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Security Agent installed on the remote host is
affected by a buffer overflow vulnerability.  By sending a specially-
crafted SMB request to the agent, an unauthenticated attacker may be
able to execute arbitrary code with SYSTEM level privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484669");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20071205-csa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f9ed6b7");
  script_set_attribute(
    attribute:"solution",
    value:
"- Cisco Security Agent version 4.5.1, upgrade to 4.5.1.672
 - Cisco Security Agent version 5.0,   upgrade to 5.0.0.225
 - Cisco Security Agent version 5.1,   upgrade to 5.1.0.106
 - Cisco Security Agent version 5.2,   upgrade to 5.2.0.238"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_csa_installed.nasl");
  script_require_keys("SMB/Cisco Security Agent/Path", "SMB/Cisco Security Agent/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/Cisco Security Agent/Version');
path = get_kb_item_or_exit('SMB/Cisco Security Agent/Path');

# Check for Cisco CSA Version
v = split(version, sep:".", keep:FALSE);

if (
  ( int(v[0]) < 4 ) ||
  ( int(v[0]) == 4 && int(v[1])  < 5 ) ||
  ( int(v[0]) == 4 && int(v[1]) == 5 && int(v[2]) < 1 ) ||
  ( int(v[0]) == 4 && int(v[1]) == 5 && int(v[2]) == 1 && int(v[3]) < 672 ) ||
  ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) == 0 && int(v[3]) < 225 ) ||
  ( int(v[0]) == 5 && int(v[1]) == 1 && int(v[2]) == 0 && int(v[3]) < 106 ) ||
  ( int(v[0]) == 5 && int(v[1]) == 2 && int(v[2]) == 0 && int(v[3]) < 238 )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(port:get_kb_item('SMB/transport'));
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Cisco Security Agent', version, path);
