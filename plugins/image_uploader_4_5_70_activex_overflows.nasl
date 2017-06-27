#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30134);
  script_version("$Revision: 1.13 $");

  script_bugtraq_id(26537);
  script_xref(name:"OSVDB", value:"50857");

  script_name(english:"Aurigma Image Uploader ActiveX Control < 4.5.70 Multiple Buffer Overflows");
  script_summary(english:"Checks version of Image Uploader ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Aurigma Image Uploader
ActiveX control that is reportedly affected by multiple stack buffer
overflows.  If a remote attacker can trick a user on the affected host
into visiting a specially crafted web page, this issue could be
leveraged to execute arbitrary code on the affected host subject to
the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Nov/493" );
 # http://www.aurigma.com/blog/2007/11/26/Security-issue-in-Image-Uploader#.U5IgGXbb5pA
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daa2bace" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Aurigma Image Uploader version 4.5.70 or later" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/31");
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

#

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{6E5E167B-1566-4316-B27F-0DDAB3484CF7}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  #
  # nb: the blog entry says the issue was introduced in 4.0.
  ver = activex_get_fileversion(clsid:clsid);
  if (
    ver && 
    ver =~ "^4\." && 
    activex_check_fileversion(clsid:clsid, fix:"4.5.70.0") == TRUE
  )
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
    if (report)
    {
      if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
      else security_hole(kb_smb_transport());
    }
  }
}
activex_end();
