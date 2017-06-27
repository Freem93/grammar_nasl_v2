#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29725);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-6331", "CVE-2007-6332", "CVE-2007-6333");
  script_bugtraq_id(26823);
  script_osvdb_id(41877, 41878, 41879);

  script_name(english:"HP Info Center ActiveX Control Multiple Remote Vulnerabilities");
  script_summary(english:"Checks version of HPInfoDLL ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
remote code execution vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the HP Quick Launch Button software, part of
the HP Info Center software installed by default on many HP and
Compaq laptop models. 

The version of this software on the remote host includes an ActiveX
control that reportedly contains three insecure methods -
'GetRegValue', 'SetRegValue', and 'LaunchApp' - that are marked as
'Safe for Scripting'.  If a remote attacker can trick a user on the
affected host into visiting a specially crafted web page, these issues
could be leveraged to manipulate the remote registry or launch 
arbitrary programs." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484880/30/0/threaded" );
 # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01300486
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a49e1bc" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as discussed in the vendor advisory above
and ensure that the version of the affected control is 2.0.0.0 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/18");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/12/14");
 script_cvs_date("$Date: 2014/04/17 21:56:22 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:info_center");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:quick_launch_button");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{62DDEB79-15B2-41E3-8834-D3B80493887A}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"2.0.0.0") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
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
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its kill bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
