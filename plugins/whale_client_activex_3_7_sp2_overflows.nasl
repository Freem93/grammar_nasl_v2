#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38734);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/04/17 21:56:22 $");

  script_cve_id("CVE-2007-2238");
  script_bugtraq_id(34532);
  script_osvdb_id(53933);
  script_xref(name:"CERT", value:"789121");
  script_xref(name:"Secunia", value:"34725");

  script_name(english:"Microsoft Whale Client Components ActiveX (WhlMgr.dll) Multiple Method Overflows");
  script_summary(english:"Checks version of control");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflows.");
  script_set_attribute(attribute:"description", value:
"The version of the Whale Client Components ActiveX control, a component
of Microsoft Whale Intelligent Application Gateway product and installed
on the remote Windows host, reportedly contains multiple stack-based
buffer overflows that can be triggered using long arguments to the
'CheckForUpdates' and 'UpdateComponents' methods.  If an attacker can
trick a user on the affected host into viewing a specially crafted HTML
document, he can leverage these issues to execute arbitrary code on the
affected system subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/dd282918.aspx");
  script_set_attribute(attribute:"solution", value:"Upgrade to Microsoft Intelligent Application Gateway 3.7 SP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Whale Intelligent Application Gateway ActiveX Control Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/11");

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

clsid = '{8D9563A9-8D5F-459B-87F2-BA842255CB9A}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  version = activex_get_fileversion(clsid:clsid);

  if (version && activex_check_fileversion(clsid:clsid, fix:"3.7") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "\n",
        "Version ", version, " of the vulnerable control is installed as :\n",
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
        "Version ", version, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its kill bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    if (report)
    {
      if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
      else security_hole(kb_smb_transport());
    }
  }
}
activex_end();
