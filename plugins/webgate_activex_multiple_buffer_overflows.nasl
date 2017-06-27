#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81702);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id(
    "CVE-2015-2093",
    "CVE-2015-2094",
    "CVE-2015-2095",
    "CVE-2015-2096",
    "CVE-2015-2097",
    "CVE-2015-2098",
    "CVE-2015-2099",
    "CVE-2015-2100"
  );
  script_bugtraq_id(
    72834,
    72835,
    72838,
    72839,
    72841,
    72843,
    72849
  );
  script_osvdb_id(
    118774,
    118775,
    118776,
    118777,
    118778,
    118888,
    118889,
    118890,
    118891,
    118892,
    118893,
    118894,
    118895,
    118896,
    118897,
    118898,
    118899,
    118900,
    118901,
    118902,
    118903,
    118904,
    118905,
    118906,
    118907,
    118908
  );

  script_name(english:"WEBGATE ActiveX Controls Multiple Buffer Overflows");
  script_summary(english:"Checks version of affected ActiveX controls.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains at least one ActiveX control that is
affected by buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host contains one or more of the following WEBGATE ActiveX
controls :

  - Control Center :
    - FileConverter.FileConverterCtrl.1
    - LoginContoller.LoginControllerCtrl.1
    - WESPDiscovery.WESPDiscoveryCtrl.1
    - WESPPlayback.WESPPlaybackCtrl.1

  - eDVR Manager :
    - WESPDiscovery.WESPDiscoveryCtrl.1
    - WESPEvent.WESPEventCtrl.1
    - WESPMonitor.WESPMonitorCtrl.1
    - WESPPTZ.WESPPTZCtrl.1
    - WESPPlayback.WESPPlaybackCtrl.1
    - WESPSerialPort.WESPSerialPortCtrl.1

  - Web Camera Server Audio :
    - WebEyeAudio.OCX

  - WinRDS :
    - WESPPlayback.WESPPlaybackCtrl.1

These controls are reportedly affected by multiple buffer overflows
that allow an attacker to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-054");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-055");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-056");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-057");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-058");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-059");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-060");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-061");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-062");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-063");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-064");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-065");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-066");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-067");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-068");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-069");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-070");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-071");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-072");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-073");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-074");
  script_set_attribute(attribute:"solution", value:
"Disable the offending ActiveX controls or uninstall the software that
provided the controls.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:webgateinc:control_center");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webgateinc:edvr_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webgateinc:webeyeaudio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webgateinc:winrds");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Locate files used by the controls.
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init');

info = "";
inst = FALSE;

clsids = make_list(
  "317AC6BB-6E8E-11D4-9BF0-005004BBFC86",
  "359742AF-BF34-4379-A084-B7BF0E5F34B0",
  "4A33C147-5243-4982-899A-A533BEDA99D1",
  "4E14C449-A61A-4BF7-8082-65A91298A6D8",
  "5A216ADB-3009-4211-AB77-F1857A99482C",
  "A13012BD-5A43-421A-B898-A6D13926210E",
  "B19147A0-C2FD-4B1F-BD20-3A3E1ABC4FC3",
  "BAAA6516-267C-466D-93F5-C504EF973837",
  "BC2CAA45-7DBB-4459-9013-3E7A2C933D21"
);

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (!file) continue;

  ver = activex_get_fileversion(clsid:clsid);
  if (!ver) continue;
  else inst = TRUE;

  if (
    report_paranoia > 1
    ||
    activex_get_killbit(clsid:clsid) == 0
  )
  {
    info +=
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file  +
      '\n  Installed version : ' + ver   +
      '\n  Fixed version     : See solution.' +
      '\n';
    if (!thorough_tests) break;
  }
}
activex_end();

if (!inst) audit(AUDIT_NOT_INST, "WebGate ActiveX control");

if (info)
{
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
}
else audit(AUDIT_INST_VER_NOT_VULN, "one or more WebGate ActiveX controls");
