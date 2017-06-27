#@DEPRECATED
#
# Disabled on 2013/01/14. Deprecated by smb_nt_ms13-008.nasl

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63372);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2012-4792");
  script_bugtraq_id(57070);
  script_osvdb_id(88774);
  script_xref(name:"CERT", value:"154201");
  script_xref(name:"EDB-ID", value:"23754");

  script_name(english:"MS KB2794220: Vulnerability in Internet Explorer Could Allow Remote Code Execution (deprecated)");
  script_summary(english:"Checks if 'Fix it' 50971 is in use.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web browser installed that is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing the workaround referenced in KB 2794220
(Microsoft 'Fix it' 50971).  This workaround mitigates a use-after-free
vulnerability in Internet Explorer.  Without this workaround enabled, an
attacker could exploit this vulnerability by tricking a user into
viewing a maliciously crafted web page, resulting in arbitrary code
execution.  This vulnerability is being actively exploited in the wild.

Note that the Microsoft 'Fix it' solution is effective only if the latest
available version of 'mshtml.dll' is installed. 

This plugin has been deprecated due to the publication of MS13-008. 
Microsoft has released updates that make the workarounds unnecessary. 
To check for those, use Nessus plugin ID 63522.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2794220");
  script_set_attribute(attribute:"solution", value:"Apply Microsoft 'Fix it' 50971.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS13-008 Microsoft Internet Explorer CButton Object Use-After-Free Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated.  Use smb_nt_ms13-008.nasl (plugin ID 63522) instead.");

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

ie_ver = hotfix_check_ie_version();
if (ie_ver !~ "^[678]\.") audit(AUDIT_INST_VER_NOT_VULN, 'IE', ie_ver);

port = kb_smb_transport();
vuln = 0;

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

systemroot = hotfix_get_systemroot();
if(!systemroot) audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');

guid = '{a1447a51-d8b1-4e93-bb19-82bd20da6fd2}';
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
    '\nNessus determined the Microsoft \'Fix it\' solution is not in use because' +
    '\nthe following file was not found :\n\n' +
    path + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

