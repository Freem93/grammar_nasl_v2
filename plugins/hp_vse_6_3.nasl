#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53624);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id("CVE-2011-1724");
  script_bugtraq_id(47523);
  script_osvdb_id(71929);
  script_xref(name:"Secunia", value:"44227");

  script_name(english:"HP Virtual Server Environment Remote Privilege Escalation");
  script_summary(english:"Checks version of HP Virtual Server Environment");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a virtualization application installed
that is affected by a privilege escalation vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its version, the HP Virtual Server Environment install
on the remote Windows host is affected by a remote privilege
escalation vulnerability that is triggered by an unspecified
condition.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22929905");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Virtual Server Environment 6.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:'cpe', value:'cpe:/a:hp:virtual_server_environment');
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  
  script_dependencies("hp_vse_installed.nasl");
  script_require_keys("SMB/HP_VSE/Version_UI");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

version_report = get_kb_item_or_exit('SMB/HP_VSE/Version_UI');
fix = '6.3'; 

if (ver_compare(ver:version_report, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/HP_VSE/Path');
    if (isnull(path)) path = 'n/a';

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, 'The host is not affected since HP Virtual Server Environment '+version_report +' is installed.');
