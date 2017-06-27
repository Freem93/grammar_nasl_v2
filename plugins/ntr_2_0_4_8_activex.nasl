#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57556);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2012-0266", "CVE-2012-0267");
  script_bugtraq_id(51374);
  script_osvdb_id(78252, 78253, 88104, 88105, 88106);
  script_xref(name:"Secunia", value:"45166");

  script_name(english:"NTR ActiveX Control < 2.0.4.8 Multiple Vulnerabilities");
  script_summary(english:"Checks control's version / kill bit");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An ActiveX control installed on the remote Windows host is affected
by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"At least one version of the NTR ActiveX control installed on the
remote Windows host is earlier than 2.0.4.8.  As such, it reportedly
is affected by the following vulnerabilities :

  - Four stack-based buffer overflows exist involving the
    'bstrUrl' parameter of the 'StartModule()' method, the
    'bstrParams' parameter of the 'Check()' method, and the
    'bstrUrl' parameter of the 'Download()' and
    'DownloadModule()' methods. (CVE-2012-0266)

  - An input validation vulnerability exists involving the
    'iModule' parameter of the 'StopModule()' method.
    (CVE-2012-0267)

If an attacker can trick a user on the affected host into visiting a
specially crafted web page, these issues could be leveraged to
execute arbitrary code on the host subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2012-1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2012-2/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/521210/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/521211/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade affected installs to version 2.0.4.8 or later as that
reportedly resolves the vulnerability."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NTR ActiveX Control StopModule() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
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


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Determine if the control is installed.
clsids = make_list(
  '{0FADB9AA-6955-4319-B538-BB1461E11A28}',
  '{11BD6F81-233F-4B62-BAFB-27ECABD3CBCF}',
  '{31C766ED-EAB7-400B-A861-86EB4001F491}',
  '{7AFFF5C9-F28D-4A93-8362-3EB66D33D849}',
  '{7BABCBE7-ECFF-4EA0-A344-1DC32458A6ED}',
  '{93B08541-9F6B-4697-9F9A-7058F1E33785}',
  '{B8634A6E-38D5-4AAE-8708-3F3DB92FF9D0}',
  '{E6ACF817-0A85-4EBE-9F0A-096C6488CFEA}',
  '{F11BFF96-CC7A-4482-819B-91EAE4C454EF}'
);
fixed_version = "2.0.4.8";
installs = 0;

info = '';
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    debug_print('activex_get_filename() returned NULL.');
    continue;
  }
  if (!file)
  {
    debug_print("There is no ActiveX control using the class id '"+clsid+"' on the host.");
    continue;
  }
  installs++;

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);

  # And check it.
  if (version && activex_check_fileversion(clsid:clsid, fix:fixed_version) == TRUE)
  {
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
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
if (info)
{
  # At this point, we want to know how many *vulnerable* installs there are.
  installs = max_index(split(info)) / 5;

  if (report_paranoia > 1)
  {
    if (installs == 1)
      report = info +
        '\nNote, though, that Nessus did not check whether the kill bit was set' +
        '\nfor the control\'s CLSID because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
    else
      report = info +
        '\nNote, though, that Nessus did not check whether the kill bits were set' +
        '\nfor the controls\' CLSIDs because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
  }
  else
  {
    if (installs == 1)
      report = info +
        '\nMoreover, its kill bit is not set so it is accessible via Internet' +
        '\nExplorer.\n';
    else
      report = info +
        '\nMoreover, their kill bits are not set so they are accessible via' +
        '\nInternet Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
  exit(0);
}
else 
{
  if (installs == 1) exit(0, 'One of the controls is installed but its kill bit is set.');
  else exit(0, 'The controls are installed but their kill bits are set.');
}
