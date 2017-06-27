#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26025);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-1688");
  script_bugtraq_id(25654);
  script_osvdb_id(37731);
  script_xref(name:"CERT", value:"171449");

  script_name(english:"PhotoParade Player PhPInfo ActiveX (PhPCtrl.dll) FileVersionof Property Overflow");
  script_summary(english:"Checks for PhPInfo ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the PhPInfo ActiveX control, included with
the PhotoParade Player software for creating slideshows of digital
pictures. 

The version of this control installed on the remote host reportedly
contains an unspecified overflow in its 'FileVersionOf' property that
could lead to arbitrary code execution on the affected system. 
Successful exploitation requires that an attacker trick a
user on the affected host into visiting a specially crafted web page." );
 script_set_attribute(attribute:"solution", value:
"Disable the use of this ActiveX control from within Internet Explorer
by setting its kill bit or remove it completely." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/12");
 script_cvs_date("$Date: 2014/04/21 21:40:26 $");
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


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{0115A685-ED24-4F7B-A08E-3BD15D84E668}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "The vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the kill bit was\n",
      "set for the control's CLSID because of the Report Paranoia setting\n",
      "in effect when this scan was run.\n"
    );
  else if (activex_get_killbit(clsid:clsid) == 0)
    report = string(
      "The vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Moreover, its kill bit is not set so it is accessible via\n",
      "Internet Explorer."
    );
  if (report) security_hole(port:kb_smb_transport(), extra:report);
}
activex_end();
