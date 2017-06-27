#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85849);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id(
    "CVE-2015-2531",
    "CVE-2015-2532",
    "CVE-2015-2536"
  );
  script_bugtraq_id(
    76600,
    76601,
    76603
  );
  script_osvdb_id(
    127206,
    127207,
    127208
  );
  script_xref(name:"MSFT", value:"MS15-104");
  script_xref(name:"IAVB", value:"2015-B-0113");

  script_name(english:"MS15-104: Vulnerabilities in Skype for Business Server and Lync Server Could Allow Elevation of Privilege (3089952)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple cross-site scripting vulnerabilities
in Skype for Business Server and Lync Server :

  - A cross-site scripting vulnerability exists in Skype for
    Business Server and Lync Server due to a failure by the
    jQuery engine to properly sanitize specially crafted
    content. An unauthenticated, remote attacker can exploit
    this vulnerability by convincing a user to open a
    malicious URL, resulting in the execution of arbitrary
    script code in the user's browser to gain information
    from web sessions. (CVE-2015-2531)

  - A cross-site scripting vulnerability exists in Lync
    Server due to improper sanitization of specially crafted
    content. An unauthenticated, remote attacker can exploit
    this vulnerability by convincing a user to open a
    malicious URL, resulting in the execution of arbitrary
    script code in the user's browser to gain information
    from web sessions. (CVE-2015-2532)

  - A cross-site scripting vulnerability exists in Skype for
    Business Server and Lync Server due to improper
    sanitization of specially crafted content. A remote,
    unauthenticated attacker can exploit this by convincing
    a user to open a malicious URL, resulting in the
    execution of arbitrary script code in the user's browser
    to gain elevated privileges. (CVE-2015-2536)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/ms15-104");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Lync Server 2013
and Skype for Business Server 2015.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date",value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln, installs;

vuln = FALSE;
installs = 0;

function check_vuln(fix, kb, name, path, ver, min_ver)
{
  local_var info;

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  # If min_ver is supplied, make sure the version is higher than the min_ver
  if (min_ver && ver_compare(ver:ver, fix:min_ver, strict:FALSE) == -1)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
  set_kb_item(name: "www/0/XSS", value: TRUE);
}

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS15-104';

kbs = make_list('3080352', '3080353', '3080355');

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

chkeys = make_array(
"3080352","{2A65AB9C-57AD-4EC6-BD4E-BD61A7C583B3}",
"3080353","{2A65AB9C-57AD-4EC6-BD4E-BD61A7C583B3}",
"3080355","{FA1B7E0D-9DA4-4BE2-A1FB-EEAA9248F5CD}"
);

chtest = make_array(
"3080352","Web Components\LWA\Ext\Bin\Lync.Client.ControlRes.dll",
"3080353","Web Components\Web Scheduler\Ext\Handler\bin\Microsoft.Rtc.Internal.WebSchedulerHandler.dll",
"3080355","Web Components\Web Scheduler\Ext\bin\Microsoft.Rtc.Internal.WebScheduler.dll"
);

names = make_array(
"3080352", "Business Server 2015 Enterprise Web App",
"3080353", "Microsoft Lync Web Components Server 2013",
"3080355", "Business Server 2015 Web Components Server"
);

minvers = make_array(
"3080352","6.0.0.0",
"3080353","5.0.0.0",
"3080355","6.0.0.0"
);

fixvers = make_array(
"3080352","6.0.9319.72",
"3080353","5.0.8308.927",
"3080355","6.0.9319.72"
);

paths = make_array();

installs = 0;
# Get all the keys we need
foreach kb (kbs)
{
  base = 'Software\\Microsoft\\Real-Time Communications\\'+chkeys[kb]+'\\';
  path = get_registry_value(handle:hklm,item:base+"InstallDir");
  ver  = get_registry_value(handle:hklm,item:base+"Version");
  if(isnull(ver) || isnull(path)) continue;

  paths[kb] = path;
  installs += 1;
}
# Close connection to registry
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if(installs == 0)
  audit(AUDIT_NOT_INST, "Microsoft Lync Server 2013 / Skype for Business Server 2015");

# Next verify component actually installed
foreach kb (kbs)
{
  if(empty_or_null(paths[kb])) continue;

  testfile = paths[kb]+chtest[kb];
  testfile = hotfix_get_fversion(path:testfile);
  if(testfile['error'] != HCF_OK) {
    installs -= 1;
    continue;
  }

  check_vuln(
    name    : names[kb],
    kb      : kb,
    path    : paths[kb]+chtest[kb],
    min_ver : minvers[kb],
    fix     : fixvers[kb],
    ver     : join(testfile["value"],sep:".")
  );
}
hotfix_check_fversion_end();

if(installs == 0)
  audit(AUDIT_NOT_INST, "Microsoft Lync Server 2013 / Skype for Business Server 2015");

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
hotfix_security_hole();
