#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55832);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_cve_id("CVE-2011-2404", "CVE-2011-4786", "CVE-2011-4787");
  script_bugtraq_id(49100, 51396, 51400);
  script_osvdb_id(74510, 78305, 78306);
  script_xref(name:"EDB-ID", value:"17697");
  script_xref(name:"EDB-ID", value:"18381");

  script_name(english:"HP Easy Printer Care Software ActiveX Control Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks for the control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An ActiveX control on the remote Windows host could allow arbitrary
remote code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the HPTicketMgr.dll ActiveX control, part of HP Easy
Printer Care Software and installed on the remote Windows host, is
affected by several vulnerabilities :

  - The 'SaveXML()' method in the XMLSimpleAccessor class
    ActiveX control is prone to a directory traversal
    attack and can be abused to write arbitrary files to the
    system and then execute them through the browser.
    (CVE-2011-2404)

  - The 'CacheDocumentXMLWithId()' method in the XMLCacheMgr
    class ActiveX control is prone to a directory traversal
    attack and can be abused to write malicious content to
    the filesystem. (CVE-2011-4786)

  - The 'LoadXML()' method in the XMLSimpleAccessor class
    ActiveX control is affected by a heap-based buffer
    overflow vulnerability. (CVE-2011-4787)

If an attacker can trick a user on the affected host into visiting a
specially crafted web page, these issues could be leverage to execute
arbitrary code on the host subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-261/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-12-013/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-12-014/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2011/Aug/141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/519191/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/521230/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2012/Jan/85"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2012/Jan/86"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Either uninstall the software as it is no longer supported by HP or
set the kill bit for the affected control."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Easy Printer Care XMLCacheMgr Class ActiveX Control Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:easy_printer_care_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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


clsids = make_list(
  '{466576F3-19B6-4FF1-BD48-3E0E1BFB96E9}',
  '{6F255F99-6961-48DC-B17E-6E1BCCBC0EE3}'
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
  if (!version) version = "unknown";

  # And check it.
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += 
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version + '\n';
   } 
}
activex_end();
if (!installs) exit(0, 'None of the affected controls were found on the remote host.');


# Report findings.
if (info)
{
  # At this point, we want to know how many *vulnerable* installs there are.
  installs = max_index(split(info)) / 4;

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
