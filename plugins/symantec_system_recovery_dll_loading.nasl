#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60161);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2012-0305");
  script_bugtraq_id(54594);
  script_osvdb_id(84124);
  script_xref(name:"IAVA", value:"2012-A-0125");

  script_name(english:"Symantec System Recovery 2011 imapi.dll Path Subversion Arbitrary DLL Injection Code Execution (SYM12-012)");
  script_summary(english:"Checks version of Symantec System Recovery");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Symantec System
Recovery 2011 earlier than Service Pack 2.  As such, it is reportedly
affected by an insecure library loading vulnerability.  If an attacker
can trick a user on the affected system into opening a specially
crafted file in the Granular Restore Option directory or the Recovery
Point Browser directory, this issue could be leveraged to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb107c6e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec System Recovery 2011 SP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:backupexec_system_recovery");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  
  script_dependencies("symantec_backup_exec_server_installed.nasl");
  script_require_keys("SMB/Symantec System Recovery/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit('SMB/Symantec System Recovery/Installed');

installs = get_kb_list('SMB/Symantec System Recovery/Installs/*');
if (isnull(installs)) exit(1, 'The \'SMB/Symantec System Recovery/Installs KB list is missing.');

info = '';
info2 = '';
foreach install (keys(installs))
{
  path = installs[install];
  version = install - 'SMB/Symantec System Recovery/Installs/';

  if (version =~ '^10\\.' && ver_compare(ver:version, fix:'10.0.2.44074') == -1)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.0.2.44074\n';
  }
  else info2 += ' and ' + version;
}

if (info)
{
  if (report_verbosity > 0) security_warning(port:get_kb_item('SMB/transport'), extra:info);
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since Symantec System Recovery ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');
