#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59718);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/09/06 20:39:14 $");

  script_cve_id("CVE-2011-4789");
  script_bugtraq_id(51398);
  script_osvdb_id(78309);

  script_name(english:"HP LoadRunner < 11.00 Patch 4 Code Execution Vulnerability");
  script_summary(english:"Checks version of HP Load Runner");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software performance testing 
application that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote Windows host is
potentially affected by a code execution vulnerability.  The
application fails to properly handle incoming packets with 
'0x00000000' as the first 32-bit value.  A remote, unauthenticated 
attacker, exploiting this flaw, could execute arbitrary code on the 
remote host subject to the privileges of the user running the affected
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-016/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522928/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP LoadRunner 11.00 Patch 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Diagnostics Server magentservice.exe Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("SMB/HP LoadRunner/Version", "SMB/HP LoadRunner/VersionUI", "SMB/HP LoadRunner/Path");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

app = 'HP LoadRunner';
version = get_kb_item_or_exit('SMB/'+app+'/Version');
verui = get_kb_item('SMB/'+app+'/VersionUI');
if (isnull(verui))
{
  ver = split(version, sep:'.', keep:FALSE);
  verui = ver[0] + '.' + ver[1] + '.0';
}

fix = '11.4.2021.0';
if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/'+app+'/Path');
    if (isnull(path)) path = 'n/a';
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + verui +
      '\n  Fixed version     : 11.4.0\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, app, verui);
