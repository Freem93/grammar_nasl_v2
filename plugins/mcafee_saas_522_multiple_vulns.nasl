
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57728);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2011-3006", "CVE-2011-3007");
  script_bugtraq_id(49088);
  script_osvdb_id(74512, 74513);
  script_xref(name:"MCAFEE-SB", value:"SB10016");

  script_name(english:"McAfee Security-as-a-Service (SaaS) < 5.2.2 ActiveX Controls Arbitrary Code Execution (SB10016)");
  script_summary(english:"Checks version of MyCioScan and MyAsUtil controls");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has ActiveX controls installed that could be
abused to execute arbitrary code remotely.");

  script_set_attribute(attribute:"description", value:
"Multiple ActiveX controls, installed on the remote Windows host as
part of McAfee Security-as-a-Service (SaaS) / Total Protection 
Service, are potentially affected by the following issues :

  - A flaw in the MyAsUtil.dll ActiveX control can be 
    exploited to execute arbitrary commands.

  - A flaw in the myCIOScn.dll ActiveX control can be
    exploited to write arbitrary data to a file on the
    affected computer.");

  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10016");
  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-11-12");
  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-11-13");

  script_set_attribute(attribute:"solution", value:"Upgrade to McAfee SaaS Endpoint Protection 5.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:saas_endpoint_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
if (activex_init() != ACX_OK) exit(1, 'activex_init() failed.');

clsids = make_list(
  '{209EBDEE-065C-11D4-A6B8-00C04F0D38B7}',
  '{0F8D1931-0575-4FA2-A550-77B28156C73C}',
  '{40C83AF8-FEA7-4A6A-A470-431EE84A0886}',
  '{4237FC7A-AF49-4E55-8E23-BD809599CBD2}',
  '{61A3F066-E5BA-484b-8B56-FA0C4D62EC09}',
  '{B220083E-EE88-4EA0-AC14-B15745FB0EC2}',
  '{C9A1E9A0-4BEF-4995-9B64-093AAE7B2DB3}',
  '{CE00833D-171C-450B-90B0-55CD86AA7988}'
);

fixed_version = '5.2.2';
installs = 0;

file_clsids = make_array();
file_versions = make_array();
vuln = 0;
foreach clsid (clsids)
{
  # Locate the file used by the control.
  file = activex_get_filename(clsid:clsid);

  if (isnull(file))
  {
    activex_end();
    debug_print('activex_get_filename() returned NULL.');
    continue;
  }
  if (!file)
  {
    debug_print('There is no ActiveX control using the class id \''+clsid+'\' on the host.');
    continue;
  }
  installs++;

  # Build a hash so we can have better reporting
  if (isnull(file_clsids[file])) file_clsids[file] = make_list();
  file_clsids[file] = make_list(file_clsids[file], clsid);

  # Get its version
  version = activex_get_fileversion(clsid:clsid);
  file_versions[file] = version;

  # And check it.
  if (version && activex_check_fileversion(clsid:clsid, fix:fixed_version) == TRUE)
  {
    file_versions[file] = version;
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
      vuln++;
      info += 
        '\n  Class identifier  : ' + clsid +
        '\n  Filename          : ' + file +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
    }
  }
}
activex_end();
if (!installs) exit(0, 'None of the affected controls were found on the remote host.');

# Report findings.
if (vuln)
{
  info = '';
  foreach file (keys(file_clsids))
  {
    clsids = file_clsids[file];
    if (!isnull(clsids))
    {
      if (max_index(clsids) > 1)
        info += '\nClass identifiers : ';
      else
        info += '\nClass identifier : ';
      foreach clsid (clsids)
      {
        if (i==0) info += clsid + '\n';
        else info += clsid + '\n';
      }
      info += 
        '  Filename          : ' + file + '\n' +
        '  Installed version : ' + file_versions[file] + '\n' +
        '  Fixed version     : 5.2.2\n';
    }
  }
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      'set for the control\'s CLSID because of the Report Paranoia setting\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else
{
  exit(0, 'No vulnerable versions of the ActiveX controls were found on the remote host.');
}
