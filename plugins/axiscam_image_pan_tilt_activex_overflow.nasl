#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35454);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-5260");
  script_bugtraq_id(33408);
  script_xref(name:"OSVDB", value:"51532");

  script_name(english:"AxisCamControl ActiveX Control Buffer Overflow");
  script_summary(english:"Checks for AxisCamControl control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contins the AxisCamControl ActiveX control, which is
used to control Axis network cameras.

This control reportedly has a stack-based buffer overflow in its
'image_pan_tilt' property.  If an attacker can trick a user on the
affected host into viewing a specially crafted HTML document, he can
leverage this issue to execute arbitrary code on the affected system
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-58/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500334/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.axis.com/techsup/software/acc/files/acc_security_update_090119.pdf" );
 script_set_attribute(attribute:"solution", value:
"Remove the affected control as recommended by the vendor's advisory" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/23");
 script_cvs_date("$Date: 2014/06/02 22:08:57 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = '{917623D1-D8E5-11D2-BE8B-00104B06BDE3}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);

  if (ver) ver = string("Version ", ver);
  else ver = string("An unknown version");
 
  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "\n",
      ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the kill bit was\n",
      "set for the control's CLSID because of the Report Paranoia setting\n",
      "in effect when this scan was run.\n"
    );
  else if (activex_get_killbit(clsid:clsid) == 0)
    report = string(
      "\n",
      ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Moreover, its kill bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );
  if (report)
  {
    if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
    else security_hole(kb_smb_transport());
  }
}
activex_end();
