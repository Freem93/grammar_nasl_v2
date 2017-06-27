#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71319);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-5054");
  script_bugtraq_id(64092);
  script_osvdb_id(100769);
  script_xref(name:"MSFT", value:"MS13-104");

  script_name(english:"MS13-104: Vulnerability in Microsoft Office Could Allow Information Disclosure (2909976)");
  script_summary(english:"Checks version of Mso.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote Windows host is
affected by an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of Microsoft Office 2013 that is
affected by an information disclosure vulnerability.  By tricking a user
into opening an Office file hosted a malicious website, an attacker
could obtain access tokens used to authenticate that user on a
SharePoint or other Microsoft Office server site."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-104");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-104';
kb = '2850064';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_versions = hotfix_check_office_version();
if (isnull(office_versions)) audit(AUDIT_NOT_INST, "Microsoft Office");

# Ensure we can get common files directory
commonfiles = hotfix_get_officecommonfilesdir(officever:"15.0");
if (!commonfiles) exit(1, "Error getting Office Common Files directory.");

vuln = FALSE;

# Office 2013
if (office_versions["15.0"])
{
  path = commonfiles + "\Microsoft Shared\Office15";
  if (hotfix_is_vulnerable(file:"Mso.dll", version:"15.0.4551.1007", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:kb)) vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
