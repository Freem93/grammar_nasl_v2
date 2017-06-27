#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59685);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2012-2175");
  script_bugtraq_id(53879);
  script_osvdb_id(82755);

  script_name(english:"IBM Lotus iNotes Upload Module ActiveX Control Attachment_Times() Method Buffer Overflow");
  script_summary(english:"Checks if control's kill bit is set");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Lotus iNotes Upload Module ActiveX Control is installed on the
remote Windows host.  The installed version of the control is affected
by a buffer overflow vulnerability in the Attachment_Times() method.
By tricking a victim into visiting a specially crafted page, an
attacker may be able to execute arbitrary code on the host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-132/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/61");
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21596862");
  script_set_attribute(
    attribute:"solution",
    value:
"Either set the kill bit for the control or see the vendor's advisory
for an updated control."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Lotus iNotes dwa85W ActiveX Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/19");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
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
include("audit.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Determine if the control is installed.
clsid = '{0F2AAAE3-7E9E-4b64-AB5D-1CA24C6ACB9C}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}


# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

info = '';
if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info += '\n  Class Identifier  : ' + clsid +
          '\n  Filename          : ' + file +
          '\n  Installed version : ' + version;
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
  exit(0, "Host not vulnerable since the control's kill bit is set.");
