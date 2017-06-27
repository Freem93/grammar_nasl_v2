#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35953);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-2644");
  script_bugtraq_id(23934);
  script_xref(name:"EDB-ID", value:"3899");
  script_xref(name:"OSVDB", value:"37786");

  script_name(english:"Morovia Barcode ActiveX Control < 3.6.0 Arbitrary File Overwrite");
  script_summary(english:"Checks version of control");
 
  script_set_attribute( attribute:"synopsis",  value:
"The remote Windows host has an ActiveX control that can be used to
overwrite arbitrary files."  );
  script_set_attribute( attribute:"description",  value:
"The version of the Morovia Barcode ActiveX control installed on the
remote Windows host allows overwriting of arbitrary files via calls to
the control's 'Save' and 'ExportImage' methods.  If an attacker can
trick a user on the affected host into viewing a specially crafted
HTML document, he can leverage this issue to overwrite arbitrary files
on the affected system subject to the user's privileges."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://mdn.morovia.com/manuals/bax3/Barcode-ActiveX-Release-Notes.htm"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Morovia Barcode ActiveX 3.6.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/11");
 script_cvs_date("$Date: 2016/05/20 14:12:06 $");
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

clsid = '{18B409DA-241A-4BD8-AC69-B5D547D5B141}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);

  if (ver && activex_check_fileversion(clsid:clsid, fix:"3.6.0") == TRUE)
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
