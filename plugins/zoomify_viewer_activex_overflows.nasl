#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25460);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-2920");
  script_bugtraq_id(24421);
  script_osvdb_id(37207);
  script_xref(name:"CERT", value:"174177");

  script_name(english:"Zoomify Viewer ActiveX Buffer Overflows");
  script_summary(english:"Checks versions of Zoomify Viewer ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
multiple buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the Zoomify Viewer ActiveX control, used to
incorporate zoomable images into websites.

The version of this control on the remote host is reportedly affected
by multiple stack-based buffer overflows.  If an attacker can trick a
user on the affected host into visiting a specially crafted web page,
these issues could be leveraged to execute arbitrary code on the host
subject to the user's privileges." );
 script_set_attribute(attribute:"solution", value:
"Disable the use of this ActiveX control from within Internet Explorer
by setting its kill bit." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/12");
 script_cvs_date("$Date: 2014/05/30 21:51:49 $");
script_set_attribute(attribute:"plugin_type", value:"local");
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

clsid = "{F7DC2A2E-FC34-11D3-B1D9-00A0C99B41BB}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "According to the registry, the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the kill bit was\n",
      "set for the control's CLSID because of the Report Paranoia setting\n",
      "in effect when this scan was run.\n"
    );
  else if (activex_get_killbit(clsid:clsid) == 0)
    report = string(
      "According to the registry, the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Moreover, its kill bit is not set so it is accessible via\n",
      "Internet Explorer."
    );
  if (report) security_hole(port:kb_smb_transport(), extra: report);
}
activex_end();
