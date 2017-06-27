#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25951);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2007-4467");
  script_bugtraq_id(25473);
  script_osvdb_id(37711);
  script_xref(name:"CERT", value:"474433");

  script_name(english:"Oracle JInitiator beans.ocx ActiveX Multiple Buffer Overflows");
  script_summary(english:"Checks for beans.ocx control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has at least one ActiveX control that is
affected by several buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains one or more versions of the 'beans.ocx'
ActiveX control, distributed as a part of Oracle JInitiator.

The version of at least one of these controls on the remote host
reportedly is affected by multiple and as-yet unspecified stack buffer
overflows in its initialization parameters.  If an attacker can trick
a user on the affected host into visiting a specially crafted web
page, this issue could be leveraged to execute arbitrary code on the
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Sep/188" );
 script_set_attribute(attribute:"solution", value:
"Disable the use of any reported ActiveX controls from within Internet
Explorer by setting their kill bits." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-300");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/08/28");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jinitiator");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate files used by the controls.
if (activex_init() != ACX_OK) exit(0);

info = "";
clsids = make_list(
  "{A2001DD0-C7BD-11D4-A3E1-00C04FA32518}",
  "{FF348B6E-FD21-11D4-A3F0-00C04FA32518}",
  "{689FF870-2AC0-11D5-B634-00C04FAEDB18}",
  "{86ECB6A0-400A-11D5-B638-00C04FAEDB18}",
  "{ED54A7B0-6C1C-11D5-B63D-00C04FAEDB18}",
  "{0A454840-7232-11D5-B63D-00C04FAEDB18}",
  "{9B935470-AD4A-11D5-B63E-00C04FAEDB18}",
  "{1D2A8890-3083-11D6-B649-00C04FAEDB18}",
  "{5E2A3510-4371-11D6-B64C-00C04FAEDB18}",
  "{E2258010-B53C-11D6-B64D-00C04FAEDB18}",
  "{B5859259-C40B-4B2A-AF9D-3BF0F634B1D5}",
  "{332BD5A0-8000-11D7-B657-00C04FAEDB18}",
  "{B13D8B3E-04A8-406F-BD35-07530D4A62DC}",
  "{E79BC654-8FC6-4BB9-BFB8-8860779AE213}",
  "{7C2C94F0-7991-42B4-8D5F-4CB15B490657}",
  "{9F77A997-F0F3-11D1-9195-00C04FC990DC}",
  "{020F6116-407B-11D3-A3BB-00C04FA32518}",
  "{152AF7C0-B73A-11D3-A3D4-00C04FA32518}",
  "{093501CE-D290-11D3-A3D6-00C04FA32518}",
  "{AF9A5360-F528-11D3-A3DA-00C04FA32518}",
  "{21157916-4D49-11D4-A3E0-00C04FA32518}",
  "{AA44DA02-7F61-11D4-A3E1-00C04FA32518}",
  "{FF348B6E-FD21-11D4-A3F0-00C04FA32518}"
);
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (
      report_paranoia > 1 ||
      activex_get_killbit(clsid:clsid) == 0
    )
    {
      info += '  ' + file + '\n';
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  report = string(
    "Nessus found the following affected control(s) installed :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the 'Perform thorough tests' setting was not enabled\n",
      "when this scan was run.\n"
    );
  }

  if (report_paranoia > 1)
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether the kill bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
    );
  else 
    report = string(
      report,
      "\n",
      "Moreover, the kill bit was  not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
    );
  security_hole(port:kb_smb_transport(), extra:report);
}
