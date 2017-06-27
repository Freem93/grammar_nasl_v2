#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25798);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-4034");
  script_bugtraq_id(25086);
  script_xref(name:"OSVDB", value:"37705");

  script_name(english:"Yahoo! Widgets YDP YDPCTL.YDPControl.1 ActiveX (YDPCTL.dll) Buffer Overflow");
  script_summary(english:"Checks versions of YDP ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the YDP ActiveX control, distributed as a
part of Yahoo! Widgets. 

The version of this control installed on the remote host reportedly
fails to validate input to the 'GetComponentVersion' method before
storing it in a 512-byte buffer.  If an attacker can trick a user on
the affected host into visiting a specially crafted web page, he may
be able to leverage this issue to execute arbitrary code on the host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://help.yahoo.com/l/us/yahoo/widgets/security/security-08.html" );
 script_set_attribute(attribute:"solution", value:
"Either disable the use of this ActiveX control from within Internet
Explorer by setting its kill bit or upgrade to Yahoo! Widgets
version 4.0.5 (version 2007.7.13.3 of the YDP control itself) or
later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/25");
 script_cvs_date("$Date: 2014/04/21 19:24:58 $");
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

clsid = "{7EC7B6C5-25BD-4586-A641-D2ACBB6629DD}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"2007.7.13.3") == TRUE)
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
    if (report) security_hole(port:kb_smb_transport(), extra: report);
  }
}
activex_end();
