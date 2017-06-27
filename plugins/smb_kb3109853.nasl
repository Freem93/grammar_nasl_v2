#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87876);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/13 02:19:35 $");

  script_name(english:"MS KB3109853: Update to Improve TLS Session Resumption Interoperability");
  script_summary(english:"Checks the version of schannel.dll.");

  script_set_attribute(attribute:"synopsis", value:"
The remote Windows host is missing an update to the TLS implementation
in SChannel.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing an update to the Transport Layer
Security (TLS) protocol implementation in SChannel. The update
improves the interoperability between Schannel-based TLS clients and
3rd-party TLS servers that enable RFC5077-based resumption and that
send the NewSessionTicket message in the abbreviated TLS handshake.
This update also addresses an issue in schannel.dll that could cause
an RFC5077 session ticket-based resumption to fail, subsequently
causing WinInet-based clients to perform a fallback to a lower TLS
protocol version than what would have been otherwise negotiated.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3109853");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 8, RT, 2012, 8.1,
RT 8.1, 2012 R2, and 10.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");

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

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"Schannel.dll", version:"10.0.10586.63", min_version:"10.0.10586.0", dir:"\system32\drivers") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"Schannel.dll", version:"10.0.10240.16644", dir:"\system32\drivers") ||

  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Schannel.dll", version:"6.3.9600.18154", min_version:"6.3.9600.16000", dir:"\system32") ||

  # Windows 8 / Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Schannel.dll", version:"6.2.9200.21708", min_version:"6.2.9200.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x86", file:"Schannel.dll", version:"6.2.9200.17592", min_version:"6.2.9200.16000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x64", file:"Schannel.dll", version:"6.2.9200.17590", min_version:"6.2.9200.16000", dir:"\system32")
)
{
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
