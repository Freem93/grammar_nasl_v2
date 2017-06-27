#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70854);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/13 08:26:15 $");

  script_name(english:"MS KB2868725: Update for Disabling RC4");
  script_summary(english:"Checks version of schannel.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has a deprecated, weak encryption cipher enabled."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing KB2868725, an update for disabling the weak
RC4 cipher suite."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2868725");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2868725.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Schannel.dll", version:"6.2.9200.20832", min_version:"6.2.9200.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Schannel.dll", version:"6.2.9200.16722", min_version:"6.2.9200.16000", dir:"\system32") ||

  # Windows 7 SP1 and Windows Server 2008 R2 SP1
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Schannel.dll", version:"6.1.7601.22465", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Schannel.dll", version:"6.1.7601.18270", min_version:"6.1.7600.17000", dir:"\system32")
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
