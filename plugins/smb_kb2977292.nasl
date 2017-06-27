#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78446);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/08/30 21:09:49 $");

  script_name(english:"MS KB2977292: Update for Microsoft EAP Implementation that Enables the Use of TLS");
  script_summary(english:"Checks the version of rastls.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing an update that allows TLS versions 1.1 and
1.2 to be used with EAP.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Microsoft KB2977292. This update allows the
latest Transport Layer Security (TLS) versions (1.1 and 1.2) to be
used with the Extensible Authentication Protocol (EAP) for more secure
authentication. Enabling this functionality requires a registry edit.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/2977292.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 2008 R2, 8,
2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"rastls.dll", version:"6.3.9600.17334", min_version:"6.3.9600.16000", dir:"\system32") ||

  # Windows 8 / Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rastls.dll", version:"6.2.9200.17103", min_version:"6.2.9200.16000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rastls.dll", version:"6.2.9200.21219", min_version:"6.2.9200.20000", dir:"\system32") ||

  # Windows 7 / Server 2008R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rastls.dll", version:"6.1.7601.22792", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rastls.dll", version:"6.1.7601.18584", min_version:"6.1.7601.17000", dir:"\system32")
)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

