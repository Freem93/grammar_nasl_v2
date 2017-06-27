#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91045);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/05/11 16:51:13 $");

  script_name(english:"MS KB3155527: Update to Cipher Suites for FalseStart");
  script_summary(english:"Checks the version of hvax64.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a cipher downgrade
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a cipher downgrade
vulnerability in FalseStart due to allowing TLS clients to send
application data before receiving and verifying the server 'Finished'
message. A man-in-the-middle attacker can exploit this to force a TLS
client to encrypt the first flight of application_data records using
an attacker's chosen cipher suite from the client's list.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3155527");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10 1511
  hotfix_is_vulnerable(os:"10", sp:0, file:"schannel.dll", version:"10.0.10586.306", min_version:"10.0.10586.0", dir:"\system32", kb:"3156421") ||
  # Windows 10
  hotfix_is_vulnerable(os:"10", file:"schannel.dll", version:"10.0.10240.16841", dir:"\system32", kb:"3156387") ||
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"schannel.dll", version:"6.3.9600.18298", min_version:"6.3.9600.16000", dir:"\system32", kb:"3151058") ||
  # Windows 2012
  hotfix_is_vulnerable(os:"6.2", file:"schannel.dll", version:"6.2.9200.21830", min_version:"6.2.9200.16000", dir:"\system32", kb:"3151058")
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
