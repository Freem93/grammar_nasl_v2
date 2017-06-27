#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74424);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-1823");
  script_bugtraq_id(67893);
  script_osvdb_id(107833);
  script_xref(name:"MSFT", value:"MS14-032");
  script_xref(name:"IAVB", value:"2014-B-0072");

  script_name(english:"MS14-032: Vulnerability in Microsoft Lync Server Could Allow Information Disclosure (2969258)");
  script_summary(english:"Checks installed versions of Lync Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Lync Server installed on the remote host is
affected by an information disclosure vulnerability that can be
exploited by tricking a user into clicking a specially crafted URL.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-032");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Lync Server 2010
and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

global_var bulletin, vuln;

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
}

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS14-032';

kbs = make_list('2963286', '2963288');

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the path information for Microsoft Lync Server 2013/2010 (Web Components Server)
lync_web_path = get_registry_value(
  handle : hklm,
  item   : 'Software\\Microsoft\\Real-Time Communications\\{2A65AB9C-57AD-4EC6-BD4E-BD61A7C583B3}\\InstallDir'
);

# Get the path information for Microsoft Lync Server 2013/2010 (Web Components Server)
lync_version = get_registry_value(
  handle : hklm,
  item   : 'Software\\Microsoft\\Real-Time Communications\\{2A65AB9C-57AD-4EC6-BD4E-BD61A7C583B3}\\Version'
);

# Close connection to registry
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (isnull(lync_web_path) || isnull(lync_version))
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, "Microsoft Lync Web Components Server 2010 or 2013");
}

# Verify install exists
# comes with 2013 installs
test_dll = lync_web_path + "\Web Components\Autodiscover\Ext\Bin\system.net.http.formatting.dll";
ver = hotfix_get_fversion(path:test_dll);

if(ver['error'] != HCF_OK)
{
  # comes with 2010 installs
  test_dll = lync_web_path + "\Web Components\Reach\Int\bin\Microsoft.Rtc.Internal.ReachJoin.dll";
  ver = hotfix_get_fversion(path:test_dll);
  hotfix_handle_error(error_code:ver['error'],
                      file:test_dll,
                      appname:"Microsoft Lync Web Components Server",
                      exit_on_fail:TRUE);
}

hotfix_check_fversion_end();

#############################################################
# Microsoft Lync Server 2013
#############################################################
if (lync_version =~ "^5\.0\.")
{
  name = "Microsoft Lync Server 2013";

  check_vuln(
    name    : name,
    kb      : "2963288",
    path    : lync_web_path,
    min_ver : "5.0.0.0",
    fix     : "5.0.8308.603",
    ver     : lync_version
  );
}

#############################################################
# Microsoft Lync Server 2010
#############################################################
if (lync_version =~ "^4\.0\.")
{
  name = "Microsoft Lync Server 2010";

  check_vuln(
    name    : name,
    kb      : "2963286",
    path    : lync_web_path,
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.231",
    ver     : lync_version
  );
}

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');

set_kb_item(name: "www/0/XSS", value: TRUE);

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
hotfix_security_warning();
