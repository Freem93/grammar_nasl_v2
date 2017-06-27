#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77575);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-4068", "CVE-2014-4070", "CVE-2014-4071");
  script_osvdb_id(111150, 111151, 111152);
  script_bugtraq_id(69579, 69586, 69592);
  script_xref(name:"MSFT",value:"MS14-055");
  script_xref(name:"IAVB", value:"2014-B-0123");

  script_name(english:"MS14-055: Vulnerability in Microsoft Lync Server Could Allow Denial of Service (2990928)");
  script_summary(english:"Checks the installed versions of Lync Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Lync Server installed on the remote host is
affected by multiple vulnerabilities :

  - The Lync Server contains a flaw in how it handles
    exceptions, which can be exploited by a remote attacker
    to cause a denial of service. (CVE-2014-4068)

  - A cross-site scripting vulnerability exists in the Lync
    Server due to a failure to properly sanitize user input.
    An attacker can exploit this to obtain sensitive
    information from web sessions. (CVE-2014-4070)

  - The Lync Server contains a flaw in how it handles
    NULL dereferences, which can be exploited by a remote
    attacker to cause a denial of service. (CVE-2014-4071)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-055");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Lync Server 2010
and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
  if(kb == "2982390") set_kb_item(name: "www/0/XSS", value: TRUE);
}

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS14-055';

kbs = make_list('2982390', '2986072', '2982389', "2992965", "2982388", "2982385");

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

chkeys = make_array(
"2982385","{A593FD00-64F1-4288-A6F4-E699ED9DCA35}",
"2992965","{A766C25B-A1D1-4711-A726-AC3E7CA4AAB3}",
"2982390","{2A65AB9C-57AD-4EC6-BD4E-BD61A7C583B3}",
"2982388","{11CFB169-07EA-489D-BF8C-D8D29525720E}",
"2982389","{11CFB169-07EA-489D-BF8C-D8D29525720E}",
"2986072","{A593FD00-64F1-4288-A6F4-E699ED9DCA35}"
);

chtest = make_array(
"2982385","Server\Core\APIEM.dll",
"2992965","Deployment\Deploy.exe",
"2982390","Web Components\Autodiscover\Ext\Bin\system.net.http.formatting.dll",
"2982388","Application Host\Applications\Response Group\Microsoft.Rtc.Acd.Workflow.dll",
"2982389","Application Host\Applications\Response Group\Microsoft.Rtc.Acd.Workflow.dll",
"2986072","Server\Core\APIEM.dll"
);

names = make_array(
"2982385","Microsoft Lync Server 2010",
"2992965","Microsoft Lync Core Components 2013",
"2982390","Microsoft Lync Web Components Server 2013",
"2982388","Microsoft Lync Response Group Service 2010",
"2982389","Microsoft Lync Response Group Service 2013",
"2986072","Microsoft Lync Server 2013"
);

minvers = make_array(
"2982385","4.0.0.0",
"2992965","5.0.0.0",
"2982390","4.0.0.0",
"2982388","4.0.0.0",
"2982389","5.0.0.0",
"2986072","5.0.0.0"
);

fixvers = make_array(
"2982385","4.0.7577.199",
"2992965","5.0.8308.420",
"2982390","4.0.21112.0",
"2982388","4.0.7577.276",
"2982389","5.0.8308.803",
"2986072","5.0.8308.726"
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
  audit(AUDIT_NOT_INST, "Microsoft Lync Server 2010 or 2013");

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

if(installs == 0) audit(AUDIT_NOT_INST, "Microsoft Lync Server 2010 or 2013");

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
hotfix_security_warning();
