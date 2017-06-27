#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35627);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-4472");
  script_bugtraq_id(31490);
  script_xref(name:"EDB-ID", value:"6630");
  script_xref(name:"OSVDB", value:"49047");

  script_name(english:"AutoDesk LiveUpdate ActiveX Control ApplyPatch Method Execution");
  script_summary(english:"Checks version of LiveUpdate control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that can be used to
execute programs." );
 script_set_attribute(attribute:"description", value:
"The version of the LiveUpdate ActiveX control, a component included
with AutoCAD-based products and installed on the remote Windows host,
reportedly allows execution of arbitrary programs via the second
argument to the control's 'ApplyPatch' method.  If an attacker can
trick a user on the affected host into viewing a specially crafted
HTML document, he can leverage these issues to execute arbitrary code
on the affected system subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_autodesk_revit_arch_2009_exploit.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496847/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c9c4525" );
 script_set_attribute(attribute:"solution", value:
"Apply the hotfix referenced in the vendor advisory above and verify
that the version of the control is 17.2.56.12 or or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/09");
 script_cvs_date("$Date: 2016/05/20 14:03:01 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

clsid = '{89EC7921-729B-4116-A819-DF86A4A5776B}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);

  if (ver && activex_check_fileversion(clsid:clsid, fix:"17.2.56.12") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "\n",
        "Version ", ver, " of the vulnerable control is installed as :\n",
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
        "Version ", ver, " of the vulnerable control is installed as :\n",
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
}
activex_end();
