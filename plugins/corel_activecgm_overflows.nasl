#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25494);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/04/17 18:47:26 $");

  script_cve_id("CVE-2007-2921");
  script_bugtraq_id(24464);
  script_osvdb_id(35468);
  script_xref(name:"CERT", value:"983249");

  script_name(english:"Corel ActiveCGM Browser ActiveX (acqm.dll) Multiple Overflows");
  script_summary(english:"Checks versions of ActiveCGM ActiveX control"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
multiple buffer overflow attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the ActiveCGM ActiveX control, which supports
viewing of CGM files in a web browser. 

The version of this control on the remote host is reportedly affected
by multiple buffer overflows.  If an attacker can trick a user on the
affected host into visiting a specially crafted web page, he may be
able to leverage these issues to execute arbitrary code on the host
subject to the user's privileges.");
  script_set_attribute(attribute:"solution", value:
"Either disable the use of this ActiveX control from within Internet
Explorer by setting its kill bit or contact the vendor to upgrade it
to version 7.1.4.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:corel:activecgm_browser");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate files used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{F5D98C43-DB16-11cf-8ECA-0000C0FD59C7}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"7.1.4.19") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "According to the registry, version '", ver, "' of the vulnerable\n",
        "control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note, though, that Nessus did not check whether the kill bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else if (activex_get_killbit(clsid:clsid) == 0)
      report = string(
        "According to the registry, version '", ver, "' of the vulnerable\n",
        "control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its kill bit is not set so it is accessible via\n",
        "Internet Explorer."
      );
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
