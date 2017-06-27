#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30219);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-0659");
  script_bugtraq_id(27533);
  script_xref(name:"EDB-ID", value:"5025");
  script_xref(name:"OSVDB", value:"40833");
  script_xref(name:"Secunia", value:"28715");

  script_name(english:"MySpace Uploader ActiveX Control < 1.0.0.6 Action Property Buffer Overflow");
  script_summary(english:"Checks version of affected ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the MySpace Uploader ActiveX
control (MySpace.Uploader.4.1) that reportedly is affected by a buffer
overflow that can be triggered by assigning a string longer than 260
characters to certain properties, such as 'Action', 'ExtractIptc', and
'ExtractExif'.  If a remote attacker can trick a user on the affected
host into visiting a specially crafted web page, this issue could be
leveraged to execute arbitrary code on the affected host subject to
the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jan/593" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.0.6 of the control as that reportedly resolves
the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/11");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
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


# Locate the file used by the control.
if (activex_init() != ACX_OK) exit(0);

clsid = "{48DD0448-9209-4F81-9F6D-D83562940134}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"1.0.0.6") == TRUE)
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
