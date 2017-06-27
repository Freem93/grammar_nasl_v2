#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72179);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2013-6040");
  script_bugtraq_id(65038);
  script_osvdb_id(102322, 102323, 102324);
  script_xref(name:"CERT", value:"219470");
  script_xref(name:"EDB-ID", value:"31176");
  script_xref(name:"EDB-ID", value:"31177");
  script_xref(name:"EDB-ID", value:"31178");

  script_name(english:"MW6 Technologies ActiveX Multiple Buffer Overflows");
  script_summary(english:"Checks if the kill bit is set on affected controls.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has one or more ActiveX controls installed that
are affected by multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has one or more ActiveX controls from MW6
Technologies ActiveX controls that are affected by multiple buffer
overflow vulnerabilities.  Specifically, these involve the 'Data'
parameter as used in the Aztec, DataMatrix, and MaxiCode controls, and
successful exploitation could lead to arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Jan/137");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/240797");
  script_set_attribute(
    attribute:"solution",
    value:
"There are currently no known fixes; as a workaround, set the kill bit
on the affected ActiveX controls."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mw6tech:aztec_activex_control");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mw6tech:datamatrix_activex_control");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mw6tech:maxicode_activex_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_activex_func.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (activex_init() != ACX_OK) exit(1, 'activex_init() failed.');

clsids = make_list(
  "{2355C601-37D1-42B4-BEB1-03C773298DC8}",
  "{DE7DA0B5-7D7B-4CEA-8739-65CF600D511E}",
  "{F359732D-D020-40ED-83FF-F381EFE36B54}"
);

report = "";

foreach clsid (clsids)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    file = activex_get_filename(clsid:clsid);
    if (!file) continue;

    # Get its version.
    version = activex_get_fileversion(clsid:clsid);
    if (!version) version = "Unknown";

    report +=
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version + '\n';
  }
}
activex_end();

if (report)
{
  if (report_paranoia > 1)
  {
    report +=
    '\n' +
    'Note, though, that Nessus did not check whether the kill bit was\n' +
    'set for each control\'s CLSID because of the Report Paranoia setting' + '\n' +
    'in effect when this scan was run.\n';
  }
  else
  {
    report +=
    '\n' +
    'Moreover, their kill bits are not set so they are accessible via Internet\n' +
    'Explorer.\n';
  }

  port = kb_smb_transport();
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port:port);
  exit(0);
}
else exit(0, "One or more affected controls were found but the kill bit was set on all of them.");
