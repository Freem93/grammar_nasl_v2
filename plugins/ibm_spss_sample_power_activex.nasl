#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66473);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id(
    "CVE-2012-5945",
    "CVE-2012-5946",
    "CVE-2012-5947",
    "CVE-2013-0593"
  );
  script_bugtraq_id(59527, 59556, 59557, 59559);
  script_osvdb_id(92814, 92844, 92845, 92846);

  script_name(english:"IBM SPSS SamplePower 3.0 < 3.0 FP 1 Multiple ActiveX Controls Arbitrary Code Execution");
  script_summary(english:"Checks if ActiveX controls have been updated or disabled");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has multiple ActiveX controls with code execution
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote install of IBM SPSS SamplePower has a vulnerable version of
one or more ActiveX controls installed.  'Vsflex8l.ocx', 'c1sizer.ocx',
'vsflex7l .ocx', and 'olch2x32.ocx' ActiveX controls have unspecified
arbitrary code execution vulnerabilities, which can be exploited by
tricking a user into opening a specially crafted web page."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-092/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-099/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-100/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-101/");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_spss_samplepower_olch2x32_activex_control_vulnerability_cve_2013_0593?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4600966d");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_spss_samplepower_vsflex7l_activex_control_vulnerability_cve_2012_5947?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2283db4");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_spss_samplepower_c1sizer_activex_control_vulnerability_cve_2012_5946?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9f56f15");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_spss_samplepower_vsflex8l_activex_control_vulnerability_cve_2012_5945?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c33d3af");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM SPSS SamplePower 3.0 FP 1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM SPSS SamplePower C1Tab ActiveX Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:spss_samplepower");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_spss_sample_power_installed.nasl");
  script_require_keys("SMB/ibm_spss_samplepower/Version");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

app = 'IBM SPSS SamplePower';
kb_base = 'SMB/ibm_spss_samplepower/';

port = kb_smb_transport();

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

if (version !~ "^3\.")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

killbit_checks = make_list(
  '{92D71E93-25A8-11CF-A640-9986B64D9618}', # olch2x32.ocx
  '{C0A63B86-4B21-11D3-BD95-D426EF2C7949}', # vsflex7l.ocx
  '{24E04EBF-014D-471F-930E-7654B1193BA9}', # c1sizer.ocx
  '{0F026C11-5A66-4C2B-87B5-88DDEBAE72A1}'  # vsflex8l.ocx
);

info = '';

error_list = make_list();

foreach clsid (killbit_checks)
{
  file = activex_get_filename(clsid:clsid);

  if (isnull(file))
  {
    error_list = make_list(error_list,
                 'activex_get_filename() for CLSID ' + clsid + ' failed.');
    continue;
  }


  if (!file)
  {
    error_list = make_list(error_list,
                 'ActiveX control for CLSID ' + clsid + ' not found.');
    continue;
  }

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);
  if (!version)
  {
    error_list = make_list(error_list,
                 'Error getting version for ActiveX control with CLSID ' +
                 clsid + '.');
    continue;
  }

  # per the patch, these controls should have kill bit set
  if (
    clsid != '{0F026C11-5A66-4C2B-87B5-88DDEBAE72A1}' && # vsflex8l.ocx
    activex_get_killbit(clsid:clsid) == 0
  )
  {
      info += '\n  Class identifier  : ' + clsid +
              '\n  Filename          : ' + file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : no fixed version available\n';
  }

  # this control can have its kill bit unset if it is up to date
  if (
    clsid == '{0F026C11-5A66-4C2B-87B5-88DDEBAE72A1}' && # vsflex8l.ocx
    ver_compare(ver:version, fix:'8.0.20122.296') == -1 &&
    activex_get_killbit(clsid:clsid) == 0
  )
  {
      info  += '\n  Class identifier  : ' + clsid +
               '\n  Filename          : ' + file +
               '\n  Installed version : ' + version +
               '\n  Fixed version     : 8.0.20122.296\n';
  }
}

activex_end();

report = '';

if (info != '')
{
  # build report
  report += '\nThe following vulnerable controls are installed and do not have a' +
            '\nkill bit set :\n' + info;

  if (max_index(error_list) > 0)
  {
    report += '\nThe results for this plugin may be incomplete due to the following' +
              '\nerrors:\n';
    foreach error (error_list)
      report += error + '\n';
  }

  if (report_verbosity > 0) security_hole(extra:report, port:port);
  else security_hole(port);
}
else
{
  audit_msg = 'No vulnerable ActiveX controls found.\n';

  if (max_index(error_list) > 0)
  {
    audit_msg += 'The results for this plugin may be incomplete due to the following errors:\n';
    foreach error (error_list)
      audit_msg += error + '\n';
    # errors, exit with failure
    exit(1, audit_msg);
  }

  # no errors, exit with success
  exit(0, audit_msg);
}
