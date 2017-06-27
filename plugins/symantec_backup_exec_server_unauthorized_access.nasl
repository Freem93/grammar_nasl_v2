#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55116);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/08/05 02:32:19 $");

  script_cve_id("CVE-2011-0546");
  script_bugtraq_id(47824);
  script_osvdb_id(73207);
  script_xref(name:"EDB-ID", value:"17517");
  script_xref(name:"Secunia", value:"44698");

  script_name(english:"Symantec Backup Exec Server Unauthorized Access (SYM11-006)");
  script_summary(english:"Checks the version of beserver.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a backup server installed that is 
affected by an unauthorized access vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its version number, the Symantec Backup Exec Server
installed on the remote Windows host is affected by an unauthorized
access vulnerability.

By performing a man-in-the-middle attack, a remote, unauthenticated 
attacker could execute arbitrary code on the host subject to the 
privileges of the user running the affected application.");

  script_set_attribute(attribute:"see_also", value:"http://www.ivizsecurity.com/security-advisory-iviz-sr-11001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0cdc33b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Backup Exec 2010 13.0 R3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("symantec_backup_exec_server_installed.nasl");
  script_require_keys("SMB/Symantec_Backup_Exec_Server/version");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit('SMB/Symantec_Backup_Exec_Server/version');
path = get_kb_item_or_exit('SMB/Symantec_Backup_Exec_Server/path');

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 11 || 
  ver[0] == 12 ||
  (ver[0] == 13 && ver[1] == 0 && ver[2] < 5204)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.0.5204.0 (2010 R3)\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(port:get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'Symantec Backup Exec Server version '+version+' is installed and thus is not affected.');
