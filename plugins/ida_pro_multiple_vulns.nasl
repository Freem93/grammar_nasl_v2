#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77750);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/19 16:35:12 $");

  script_osvdb_id(111541, 111463, 111462, 111461, 111460);
  script_xref(name:"IAVB", value:"2014-B-0125");

  script_name(english:"IDA Pro Multiple Memory Corruption Vulnerabilities");
  script_summary(english:"Checks for the presence of the mitigating IDA Pro patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IDA Pro, an interactive disassembler installed on the
remote host, is 6.5 or 6.6. It is, therefore, affected by memory
corruption vulnerabilities.

These vulnerabilities are mitigated by updated IDA loaders, which were
not detected.

By tricking a user into loading a specially crafted IDB (IDA database)
file into IDA Pro, an attacker can cause a denial of service or
execute arbitrary code or have other unspecified impact.");
  script_set_attribute(attribute:"see_also", value:"https://www.hex-rays.com/vulnfix.shtml");
  script_set_attribute(attribute:"solution", value:"Install the fix provided by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:datarescue:ida_pro");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

port = kb_smb_transport();
appname = 'IDA Pro';
magic1 = 'NO SUCH TAG';
magic2 = 'dex: failed to read dexcode!';
exe = '\\idaq.exe';
loader = '\\loaders\\dex.ldw';

locations = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/IDA Pro*/InstallLocation");
if (isnull(locations)) audit(AUDIT_NOT_INST, appname);

report = "";
vulnerable = FALSE;
not_vuln_versions = make_list();

# Check each installed copy of IDA
foreach key (keys(locations))
{
  path = get_kb_item_or_exit(key);

  version_vulnerable = FALSE;

  ver = hotfix_get_fversion(path:path + exe);

  if (ver['error'] == HCF_NOAUTH)
  {
    # Go ahead and exit because share or creds are the issue
    hotfix_handle_error(error_code: ver['error'], appname:appname, file:path + exe, exit_on_fail:TRUE);
  }
  else if (ver['error'] != HCF_OK)
  {
    continue;
  }

  # Only want to check up to first two parts of version
  if (max_index(ver['value']) > 2)
  {
    version_cmp = join(make_list(ver['value'][0], ver['value'][1]), sep:'.');
  }
  else
  {
    version_cmp = join(ver['value'], sep:'.');
  }

  version = join(ver['value'], sep:'.');

  if (ver_compare(ver:version_cmp, fix:'6.5', strict:FALSE) == -1 || ver_compare(ver:version_cmp, fix:'6.6', strict:FALSE) == 1)
  {
    not_vuln_versions[max_index(not_vuln_versions)] = version;
  }
  else
  {
    contents = hotfix_get_file_contents(path:path + loader);
    if (contents['error'] != HCF_OK)
    {
      not_vuln_versions[max_index(not_vuln_versions)] = version;
    }

    if(magic1 >< contents['data'] || magic2 >< contents['data'])
    {
      not_vuln_versions[max_index(not_vuln_versions)] = version;
    }
    else
    {
      version_vulnerable = TRUE;
    }
  }

  if (version_vulnerable)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + '\n';
    vulnerable = TRUE;
  }
}

hotfix_check_fversion_end();

if (vulnerable)
{
  if (report_verbosity > 0) security_warning(extra:report, port:port);
  else security_warning(port);
}
else if (isnull(not_vuln_versions) || max_index(not_vuln_versions) == 0) audit(AUDIT_NOT_INST, appname);
else audit(AUDIT_INST_VER_NOT_VULN, appname, not_vuln_versions);
