#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61528);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-2526");
  script_bugtraq_id(54935);
  script_osvdb_id(84602);
  script_xref(name:"MSFT", value:"MS12-053");

  script_name(english:"MS12-053: Vulnerability in Remote Desktop Could Allow Remote Code Execution (2723135)");
  script_summary(english:"Checks version of Rdpwd.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host is affected by a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An arbitrary remote code vulnerability exists in the implementation
of the Remote Desktop Protocol (RDP) on the remote Windows host. The
vulnerability is due to the way that RDP accesses an object in memory
that has been deleted.

If RDP has been enabled on the affected system, an unauthenticated,
remote attacker could leverage this vulnerability to cause the system
to execute arbitrary code by sending a sequence of specially crafted
RDP packets to it.

Note that the Remote Desktop Protocol is not enabled by default."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523921/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-053");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_xp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS12-053";
kb = "2723135";
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Only XP SP:3 is affected
if (hotfix_check_sp_range(xp:'3') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Rdpwd.sys", version:"5.1.2600.6258", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
