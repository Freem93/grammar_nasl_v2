#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31724);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-5661");
  script_bugtraq_id(28533);
  script_osvdb_id(43956);
  script_xref(name:"Secunia", value:"29549");

  script_name(english:"Macrovision InstallShield InstallScript One-Click Install ActiveX Arbitrary Code Execution");
  script_summary(english:"Checks version of One-Click Install ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the InstallScript One-Click Install ActiveX
control distributed with Macrovision's InstallShield.

The installed version of that control reportedly allows an attacker to
download arbitrary DLL files from a website to be executed as part of
a web install.  If a remote attacker can trick a user on the affected
host into visiting a specially crafted web page, this issue could be
leveraged to execute arbitrary code on the affected host subject to
the user's privileges." );
 # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=649
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6772e50" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Mar/599" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to InstallShield 12 Service Pack 2 if necessary, apply the
appropriate hotfix, and then rebuild and update any HTML files as
described in the vendor's advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/01");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

clsid = "{53D40FAA-4E21-459f-AA87-E4D97FC3245A}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (
    ver && 
    ver =~ "^12\." &&
    activex_check_fileversion(clsid:clsid, fix:"12.0.0.58855") == TRUE
  )
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
