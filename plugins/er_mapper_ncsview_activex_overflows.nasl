#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26014);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-4470");
  script_bugtraq_id(25584);
  script_osvdb_id(37780);
  script_xref(name:"CERT", value:"589188");

  script_name(english:"ER Mapper NCSView ActiveX Multiple Buffer Overflows");
  script_summary(english:"Checks version of NCSView ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the 'NCSView' ActiveX control, distributed as
part of the ER Mapper package and used to view maps in Internet
Explorer.

The version of this control installed on the remote host reportedly
contains multiple stack-based buffer overflows.  If an attacker can
trick a user on the affected host into visiting a specially crafted
web page, this issue could be leveraged to execute arbitrary code on
the host subject to the user's privileges." );
 script_set_attribute(attribute:"solution", value:
"Either disable the use of this ActiveX control from within Internet
Explorer by setting its kill bit or upgrade to ER Mapper version 8.1
(version 3.4.0.242 of the NCSView control itself) or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/06");
 script_cvs_date("$Date: 2014/06/03 21:39:48 $");
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

#

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{8EC18CE2-D7B4-11D2-88C8-006008A717FD}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"3.4.0.242") == TRUE)
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
        "Moreover, its kill bit is not set so it is accessible via\n",
        "Internet Explorer."
      );
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
