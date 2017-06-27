#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66419);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/11/20 22:07:59 $");

  script_cve_id("CVE-2013-1301");
  script_bugtraq_id(59765);
  script_osvdb_id(93316);
  script_xref(name:"MSFT", value:"MS13-044");

  script_name(english:"MS13-044: Vulnerability in Microsoft Visio Could Allow Information Disclosure (2834692)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"The remote Visio install is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that is affected
by an information disclosure vulnerability due to a flaw in the way
Visio parses specially crafted XML files containing external entities.

By tricking a user into opening a specially crafted file with Visio, a
remote attacker may be able to read files on the target system.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-044");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visio 2010 SP1,
Microsoft Visio 2007 SP3, and Microsoft Visio 2003 SP3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-044';
kbs = make_list("2596595", "2810062", "2810068");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");

vuln = FALSE;

installs = get_kb_list("SMB/Office/Visio/*/VisioPath");

if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Visio/' - '/VisioPath';
    if ("14.0" >< install || "12.0" >< install || "11.0" >< install)
    {
      path = installs[install];
      share = hotfix_path2share(path:path);

      if (is_accessible_share(share:share))
      {
        # Visio 2010 SP1
        if ("14.0" >< version)
        {
          # Avoid false positives that might arise if Nessus failed to fully 
          # enumerate the Uninstall registry entries.
          get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated", exit_code:1);

          visio2010sp2 = FALSE;
          list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
          if (!empty_or_null(list))
          {
            foreach key (keys(list))
            {
              if ('Service Pack 2 for Microsoft Visio 2010' >< list[key])
              {
                visio2010sp2 = TRUE;
                break;
              }
            }
            if (!visio2010sp2 && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.7100.5000", min_version:"14.0.6000.0", bulletin:bulletin, kb:"2810068")) vuln = TRUE;
          }
        }
        if (
          # Visio 2007 SP3
          (
            "12.0" >< version &&
            hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"12.0.6676.5000", min_version:"12.0.6600.0", bulletin:bulletin, kb:"2596595")
          ) ||
          # Visio 2003 SP3
          (
            "11.0" >< version &&
            hotfix_is_vulnerable(path:path, file:"Visio11\Visbrgr.dll", version:"11.0.8402.0", min_version:"11.0.8000.0", bulletin:bulletin, kb:"2810062")
          )
        ) vuln = TRUE;
      }
    }
  }
}
else audit(AUDIT_KB_MISSING, "SMB/Office/Visio");

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
