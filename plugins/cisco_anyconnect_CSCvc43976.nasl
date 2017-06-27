#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97226);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2017-3813");
  script_bugtraq_id(96145);
  script_osvdb_id(151766);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170208-anyconnect");
  script_xref(name:"IAVA", value:"2017-A-0040");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc43976");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 4.0.x < 4.3.05017 / 4.4.x < 4.4.00243 SBL Module Privilege Escalation");
  script_summary(english:"Checks the version of the Cisco AnyConnect client and affected module.");

  script_set_attribute(attribute:"synopsis", value:
"A VPN application installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco AnyConnect Secure Mobility Client installed on
the remote Windows host is 4.0.x prior to 4.3.05017 or 4.4.x prior to
4.4.00243. It is, therefore, affected by a privilege escalation
vulnerability in the Start Before Logon (SBL) module due to
insufficient access controls. A local attacker can exploit this to
open Internet Explorer with SYSTEM level privileges.

Note that the SBL module is not installed by default.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170208-anyconnect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b0700b1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc43976");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version 4.3.05017 /
4.4.00243 or later. Alternatively, either remove the SBL module or set
'UseStartBeforeLogon' to false in the client profile XML file.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix = '';
errors = make_list();

if (ver =~ "^4\.4\." && ver_compare(ver:ver, fix:'4.4.243', strict:FALSE) < 0)
  fix = '4.4.243';

else if (ver =~ "^4\.[0-3]\." && ver_compare(ver:ver, fix:'4.3.5017', strict:FALSE) < 0)
  fix = '4.3.5017';

if (empty(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

# Check for module uninstall entry
module      = "Cisco AnyConnect Start Before Login Module";
module_path = NULL;

display_names = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
foreach key (keys(display_names))
{
  if (display_names[key] == module)
  {
    key = key - "DisplayName" + "InstallLocation";
    module_path = get_kb_item(key);
    break;
  }
}
if (empty_or_null(module_path)) audit(AUDIT_NOT_INST, module);

# Check for module DLL
registry_init();

dlls = make_list("vpnplap.dll", "vpnplap64.dll");
dll_found = FALSE;
foreach dll (dlls)
{
  dll = module_path + dll; 
  if (hotfix_file_exists(path:dll))
  {
    dll_found = TRUE;
    break;        
  } 
}
if (!dll_found)
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, module);
}

# Check each profile
programdata = hotfix_get_programdata(exit_on_fail:TRUE);
profile_dir = hotfix_append_path(path:programdata, value:"\Cisco\Cisco AnyConnect Secure Mobility Client\Profile");
sbl_profiles = make_list();

share    = hotfix_path2share(path:profile_dir);
base_dir = ereg_replace(string:profile_dir, pattern:"^\w:(.*)", replace:"\1");
profiles = list_dir(basedir:base_dir, level:1, file_pat:".*\.xml$", share:share);

foreach profile (profiles)
{
  profile  = (share  - '$') + ':' + profile;
  contents = hotfix_get_file_contents(profile);
  error = hotfix_handle_error(error_code:contents['error'], file:profile, exit_on_fail:FALSE);
  if (error)
  {
    errors = make_list(errors, error);
    continue;
  }

  pattern = "^\s*<UseStartBeforeLogon.*>true</UseStartBeforeLogon>";
  if (preg(string:contents['data'], pattern:pattern, icase:TRUE, multiline:TRUE))
    sbl_profiles = make_list(sbl_profiles, profile);  
}

hotfix_check_fversion_end();

if (max_index(sbl_profiles) == 0)
{
  if (max_index(errors) == 0)
    audit(AUDIT_HOST_NOT, "affected because the 'UseStartBeforeLogon' option is not enabled on any Cisco AnyConnect profiles");
  else if (max_index(errors) == 1)
    exit(1, "The following error has occurred : " + errors[0]);
  else
    exit(1, "The following errors have occurred : " + join(errors, sep:";"));
}

wording = NULL;

if (max_index(sbl_profiles) == 1)
  wording = 'profile has';
else
  wording = 'profiles have';

report =
  '\n  Cisco bug ID      : CSCvc43976' +
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n' +
  '\nThe following Cisco AnyConnect ' + wording + ' the \'UseStartBeforeLogon\' option enabled :\n' +
  '\n  - ' + join(sbl_profiles, sep:'\n  - ');

security_report_v4(port:kb_smb_transport(), severity:SECURITY_WARNING, extra:report);
