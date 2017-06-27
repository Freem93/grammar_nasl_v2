#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(57729);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id("CVE-2011-1388", "CVE-2011-1391", "CVE-2011-1392");
  script_bugtraq_id(51184);
  script_osvdb_id(77994);

  script_name(english:"Blueberry FlashBack SDK 'BB FlashBack Recorder.dll' Remote Code Execution");
  script_summary(english:"Checks the version of 'BB FlashBack Recorder.dll' ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control installed that is affected by
multiple remote code execution vulnerabilities. "
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a vulnerable version of the Blueberry
'BB FlashBack Recorder.dll' control installed.  This control is
affected by multiple unspecified remote code execution
vulnerabilities related the 'FBRecorder' class and the 'Start()',
'PauseAndSave()', 'InsertMarker()', 'InsertSoundToFBRAtMarker()', and
'TestCompatibilityRecordMode()' methods.  By tricking a victim into
visiting a specially crafted web page, an attacker could take
advantage of one of these issues to execute arbitrary code in the
context of the application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-028");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-029");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-030");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/521546/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/521547/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://www.securityfocus.com/archive/1/521548/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21576352");
  script_set_attribute(attribute:"see_also",value:"http://www.bbsoftware.co.uk/BBFlashBack/Home.aspx");
  script_set_attribute(
    attribute:"solution",
    value:
"If you are running IBM Rational Rhapsody 7.6 or earlier, see the IBM
advisory for upgrade instructions.  Otherwise, either upgrade the
control to version 2.0.0.214 (or greater), remove the software, or set
the kill bit for the affected control."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/30");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:.bbsoftware:bb_flashback");
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


clsid = '{A3CD4BF9-EC17-47A4-833C-50A324D6FF35}';


# Locate the file used by the control.
file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "A control with class id '"+clsid+"' does not exist on the remote host.");
}

# Get its version
version_ui = activex_get_fileversion(clsid:clsid);
if (isnull(version_ui))
{
  activex_end();
  exit(1,  "Failed to get the file version of '"+file+"'.");
}

# check version
fixed_version = "2.0.0.214";
info = '';
rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
if (rc == TRUE)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += '\n  Class Identifier  : ' + clsid +
            '\n  Filename          : ' + file +
            '\n  Installed version : ' + version_ui +
            '\n  Fixed version     : ' + fixed_version + '\n';
  }
}
activex_end();

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
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
  if (rc == FALSE) exit(0, "The control is not affected since it is version "+version_ui+".");
  else if (rc == TRUE) exit(0, "Version "+version_ui+" of the control is installed, but its kill bit is set.");
  else exit(1, "activex_check_fileversion() failed.");
}
