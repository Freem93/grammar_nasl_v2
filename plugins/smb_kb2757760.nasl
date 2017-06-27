# @DEPRECATED@
#
# Disabled on 2012/09/21. Deprecated by smb_nt_ms12-063.nasl

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62201);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/06/03 17:46:08 $");

  script_cve_id("CVE-2012-4969");
  script_bugtraq_id(55562);
  script_osvdb_id(85532);
  script_xref(name:"CERT", value:"480095");

  script_name(english:"MS KB2757760: Vulnerability in Internet Explorer Could Allow Remote Code Execution (deprecated)");
  script_summary(english:"Checks if 'Fix it' 50939 is in use.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing the workaround referenced in KB 2757760
(Microsoft 'Fix it' 50939).  This workaround mitigates a use-after-free
vulnerability in Internet Explorer.  Without this workaround enabled,
an attacker could exploit this vulnerability by tricking a user into
view a maliciously crafted web page, resulting in arbitrary code
execution.  This vulnerability is being actively exploited in the
wild.

This plugin has been deprecated due to the publication of MS12-063.
Microsoft has released patches that make the workarounds
unnecessary.  To check for the patches, use Nessus plugin ID 62223."
  );
  # http://eromang.zataz.com/2012/09/16/zero-day-season-is-really-not-over-yet/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd827909");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2757760");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2757760");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Internet Explorer execCommand Use-After-Free Vulnerability ');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated.  Use smb_nt_ms12-063.nasl (plugin ID 62223) instead.");

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1)
  audit(AUDIT_WIN_SERVER_CORE);

port = kb_smb_transport();
vuln = 0;

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

systemroot = hotfix_get_systemroot();
guid = '{777afb2a-98e5-4f14-b455-378a925cae15}';
path = get_registry_value(handle:handle, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\" + guid);

if (isnull(path))
  path = systemroot + "\AppPatch\Custom\" + guid + '.sdb';

RegCloseKey(handle:handle);
close_registry(close:FALSE);

# Now make sure the file is in place
if (hotfix_file_exists(path:path))
  vuln = FALSE;
else
  vuln = TRUE;

hotfix_check_fversion_end();

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  report =
    '\nNessus determined the workaround is not in use because the following' +
    '\nfile was not found :\n\n' +
    path + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

