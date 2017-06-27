#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62466);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/12/05 14:10:15 $");

  script_name(english:"MS KB2661254: Update For Minimum Certificate Key Length");
  script_summary(english:"Check version of crypt32.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is configured to trust SSL/TLS certificates
with weak keys."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing Microsoft KB2661254. This update restricts
the use of RSA keys less than 1024 bits in length. Keys of shorter
lengths are more susceptible to brute-force attacks, which could allow
a man-in-the-middle attacker to intercept and/or modify data encrypted
over SSL/TLS."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2661254");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2661254");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2. 

Please note this update could cause applications or services (e.g.,
email, signed applications, private PKI) to stop working in some
environments.  Refer to the Microsoft advisory for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.22010", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.17856", min_version:"6.1.7601.17000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"crypt32.dll", version:"6.1.7600.21225", min_version:"6.1.7600.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"crypt32.dll", version:"6.1.7600.17035", min_version:"6.1.7600.16000", dir:"\system32") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"crypt32.dll", version:"6.0.6002.22869", min_version:"6.0.6002.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"crypt32.dll", version:"6.0.6002.18643", min_version:"6.0.6002.18000", dir:"\system32") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"crypt32.dll", version:"5.131.3790.5014", dir:"\system32") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"crypt32.dll", version:"5.131.2600.6239", dir:"\system32")
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

