#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45511);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id(
    "CVE-2010-0024",
    "CVE-2010-0025",
    "CVE-2010-1689",
    "CVE-2010-1690"
  );
  script_bugtraq_id(39308, 39381, 39908, 39910);
  script_osvdb_id(63738, 63739, 64793, 64794);
  script_xref(name:"MSFT", value:"MS10-024");
  script_xref(name:"IAVB", value:"2010-B-0029");

  script_name(english:"MS10-024: Vulnerabilities in Microsoft Exchange and Windows SMTP Service Could Allow Denial of Service (981832)");
  script_summary(english:"Checks versions of Smtpsvc.dll or Exchange-specific files");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote mail server may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Microsoft Exchange / Windows SMTP Service
is affected by at least one vulnerability :

  - Incorrect parsing of DNS Mail Exchanger (MX) resource
    records could cause the Windows Simple Mail Transfer
    Protocol (SMTP) component to stop responding until
    the service is restarted. (CVE-2010-0024)

  - Improper allocation of memory for interpreting SMTP
    command responses may allow an attacker to read random
    email message fragments stored on the affected server.
    (CVE-2010-0025)

  - Predictable transaction IDs are used, which could allow
    a man-in-the-middle attacker to spoof DNS responses.
    (CVE-2010-1689)

  - There is no verification that the transaction ID of a
    response matches the transaction ID of a query, which
    could allow a man-in-the-middle attacker to spoof DNS
    responses. (CVE-2010-1690)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-024");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
and 2008 as well as Exchange Server 2000, 2003, 2007, and 2010."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-024';
kbs = make_list("976323", "976702", "976703", "981383", "981401", "981407");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",       arch:"x64", file:"Smtpsvc.dll", version:"7.5.7600.20660", min_version:"7.5.7600.20000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||
  hotfix_is_vulnerable(os:"6.1",       arch:"x64", file:"Smtpsvc.dll", version:"7.5.7600.16544", min_version:"7.5.7600.16000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||

  # Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Smtpsvc.dll", version:"7.0.6002.22354", min_version:"7.0.6002.22000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Smtpsvc.dll", version:"7.0.6002.18222", min_version:"7.0.6002.18000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Smtpsvc.dll", version:"7.0.6001.22648", min_version:"7.0.6001.22000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Smtpsvc.dll", version:"7.0.6001.18440", min_version:"7.0.6001.18000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Smtpsvc.dll", version:"6.0.3790.4675",                                dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Smtpsvc.dll", version:"6.0.2600.5949",                                dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Smtpsvc.dll", version:"6.0.2600.3680",                                dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Smtpsvc.dll", version:"5.0.2195.7381",                                dir:"\system32\inetsrv", bulletin:bulletin, kb:"976323")
  )
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}

# Check Exchange Server.
version = get_kb_item("SMB/Exchange/Version");
if (version)
{
  # 2000
  if (version == 60)
  {
    sp = get_kb_item("SMB/Exchange/SP");
    if (sp && sp > 3)
    {
      hotfix_check_fversion_end();
      exit(0, "Exchange Server 2000 Service Pack "+sp+" is installed and thus not affected.");
    }

    rootfile = get_kb_item("SMB/Exchange/Path");
    if (!rootfile)
    {
      hotfix_check_fversion_end();
      audit(AUDIT_KB_MISSING, 'SMB/Exchange/Path');
    }
    rootfile = rootfile + "\bin";

    if (
      hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.0.6620.15", bulletin:bulletin, kb:"976703") == HCF_OLDER ||
      hotfix_check_fversion(path:rootfile, file:"Store.exe",  version:"6.0.6620.15", bulletin:bulletin, kb:"976703") == HCF_OLDER
    )
    {
      set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
      hotfix_security_warning();

      hotfix_check_fversion_end();
      exit(0);
    }
  }
  # 2003
  else if (version == 65)
  {
    sp = get_kb_item ("SMB/Exchange/SP");
    if (sp && sp > 2)
    {
      hotfix_check_fversion_end();
      exit(0, "Exchange Server 2003 Service Pack "+sp+" is installed and thus not affected.");
    }

    rootfile = get_kb_item("SMB/Exchange/Path");
    if (!rootfile)
    {
      hotfix_check_fversion_end();
      audit(AUDIT_KB_MISSING, 'SMB/Exchange/Path');
    }
    rootfile = rootfile + "\bin";

    if (
      hotfix_check_fversion(path:rootfile, file:"Msgfilter.dll", version:"6.5.7656.2", bulletin:bulletin, kb:"976702") == HCF_OLDER ||
      hotfix_check_fversion(path:rootfile, file:"Turflist.dll",  version:"6.5.7656.2", bulletin:bulletin, kb:"976702") == HCF_OLDER
    )
    {
      set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
      hotfix_security_warning();

      hotfix_check_fversion_end();
      exit(0);
    }
  }
  # 2007
  else if (version == 80)
  {
    sp = get_kb_item ("SMB/Exchange/SP");
    if (sp && sp > 2)
    {
      hotfix_check_fversion_end();
      exit(0, "Exchange Server 2007 Service Pack "+sp+" is installed and thus not affected.");
    }

    rootfile = get_kb_item("SMB/Exchange/Path");
    if (!rootfile)
    {
      hotfix_check_fversion_end();
      audit(AUDIT_KB_MISSING, 'SMB/Exchange/Path');
    }
    rootfile = rootfile + "\bin";

    dll = "Microsoft.Exchange.Setup.Common.dll";
    if (
      hotfix_check_fversion(path:rootfile, file:dll, version:"8.2.254.0", min_version:"8.2.0.0", bulletin:bulletin, kb:"981383") == HCF_OLDER ||
      hotfix_check_fversion(path:rootfile, file:dll, version:"8.1.436.0", min_version:"8.1.0.0", bulletin:bulletin, kb:"981407") == HCF_OLDER
    )
    {
      set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
      hotfix_security_warning();

      hotfix_check_fversion_end();
      exit(0);
    }
  }
  # 2010
  else if (version == 140)
  {
    sp = get_kb_item ("SMB/Exchange/SP");
    if (sp && sp > 0)
    {
      hotfix_check_fversion_end();
      exit(0, "Exchange Server 2010 Service Pack "+sp+" is installed and thus not affected.");
    }

    rootfile = get_kb_item("SMB/Exchange/Path");
    if (!rootfile)
    {
      hotfix_check_fversion_end();
      audit(AUDIT_KB_MISSING, 'SMB/Exchange/Path');
    }
    rootfile = rootfile + "\bin";

    if (
      hotfix_check_fversion(path:rootfile, file:"Microsoft.Exchange.Diagnostics.dll",  version:"14.0.694.0", bulletin:bulletin, kb:"981401") == HCF_OLDER ||
      hotfix_check_fversion(path:rootfile, file:"Microsoft.Exchange.Setup.Common.dll", version:"14.0.694.0", bulletin:bulletin, kb:"981401") == HCF_OLDER
    )
    {
      set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
      hotfix_security_warning();

      hotfix_check_fversion_end();
      exit(0);
    }
  }
}

hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
