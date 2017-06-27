#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#

include("compat.inc");

if (description)
{
  script_id(59461);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/01/13 03:33:22 $");

  script_cve_id("CVE-2012-1889");
  script_bugtraq_id(53934);
  script_osvdb_id(82873);
  script_xref(name:"EDB-ID", value:"19186");

  script_name(english:"MS KB2719615: Vulnerability in Microsoft XML Core Services Could Allow Remote Code Execution");
  script_summary(english:"Checks for workaround");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through a web 
browser.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the workaround referenced in KB 2719615.

An issue exists in Microsoft XML Core Services 3.0, 4.0, 5.0, and 6.0 
when the application attempts to access an object in memory that has 
not been initialized, which may corrupt memory in such a way that an 
attacker could execute arbitrary code in the context of the logged-on
user.");
  script_set_attribute(attribute:"solution", value:"Apply the Microsoft suggested workaround.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2719615");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2719615");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'windows/browser/msxml_get_definition_code_exec.rb');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

# This script has been disabled and is intended to be blank.
# Disabled on 2012/07/10.  Deprecated by smb_nt_ms12-043.nasl.
exit(0, "Deprecated - replaced by smb_nt_ms12-043.nasl");

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:2) <= 0) exit(0, 'The host is not affected based on its version / service pack.');
if ('Windows Embedded' >< get_kb_item_or_exit('SMB/ProductName'))
  audit(AUDIT_INST_VER_NOT_VULN, 'Windows Thin OS');

vuln = 0;

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
items = make_list(
  "{f300e352-12de-4e7f-ace3-a376874402b6}",
  "{29447369-6968-4e86-a208-603f6f0771a6}",
  "{06b2b7ed-809a-44e6-8538-ca0f5b74ecc4}"
);

systemroot = hotfix_get_systemroot();
paths = make_list();
foreach item (items)
{
  path = get_registry_value(handle:handle, item:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\'+item+'\\DatabasePath');
  if (!isnull(path))
    paths = make_list(paths, path);
  else paths = make_list(paths, systemroot+'\\AppPatch\\Custom\\'+item+'.sdb');
}
RegCloseKey(handle:handle);
close_registry(close:FALSE);

# Now make sure the files are in place
foreach path (paths)
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
  sdb = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    close_registry(close:FALSE);
    debug_print('Failed to connect to the \''+share+'\'.');
    continue;
  }

  fh = CreateFile(
    file:sdb,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
    vuln++;
  else
    CloseFile(handle:fh);
  close_registry(close:FALSE);
}
NetUseDel();

if (vuln)
{
  security_hole(port:port);
  exit(0);
}
else exit(0, 'The host is not affected.');
