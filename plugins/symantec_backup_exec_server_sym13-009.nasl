#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69263);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2013-4676", "CVE-2013-4677", "CVE-2013-4678");
  script_bugtraq_id(61486, 61487, 61488);
  script_osvdb_id(95939, 95940, 95941, 95942);
  script_xref(name:"IAVA", value:"2013-A-0156");

  script_name(english:"Symantec Backup Exec Server Multiple Vulnerabilities (SYM13-009)");
  script_summary(english:"Checks the version of beserver.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a backup server that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Symantec Backup Exec Server
installed on the remote Windows host is affected by multiple
vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist in
    the management console and the beutility console.
    (CVE-2013-4676)

  - Backup and restore data files are stored with weak ACLs,
    allowing read/write access to everyone. (CVE-2013-4677)

  - The NMDP protocol leaks host versioning information.
    (CVE-2013-4678)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20130801_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd76cf64");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Backup Exec 2010 R3 SP3, 2012 SP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_backup_exec_server_installed.nasl");
  script_require_keys("SMB/Symantec_Backup_Exec_Server/version");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include("audit.inc");

version = get_kb_item_or_exit('SMB/Symantec_Backup_Exec_Server/version');
path = get_kb_item_or_exit('SMB/Symantec_Backup_Exec_Server/path');

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = '';
if (ver[0] == 13 && ver_compare(ver:version, fix:'13.0.5204.1225') < 0) fix = '13.0.5204.1225 (2010 R3 SP3)';
else if (ver[0] == 14 && ver_compare(ver:version, fix:'14.0.1798.1244') < 0) fix = '14.0.1798.1244 (2012 SP2)';

if (fix)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(port:get_kb_item('SMB/transport'));
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Backup Exec Server', version, path);
