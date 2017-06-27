#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34021);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-3480");
  script_bugtraq_id(30545);
  script_xref(name:"OSVDB", value:"47592");
  script_xref(name:"Secunia", value:"31554");

  script_name(english:"Anzio Web Print Object (WePO) ActiveX mainurl Parameter Buffer Overflow");
  script_summary(english:"Checks version of WePO control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX component that is susceptible
to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the Anzio Web Print Object (WePO) ActiveX
component, which is used for 'push' printing from a web page or
application.

The version of the control installed on the remote host reportedly
contains a stack-based buffer overflow that can be triggered by
passing long values of its 'mainurl' parameter.  If an attacker can
trick a user on the affected host into viewing a specially crafted
HTML document, this method could be used to execute arbitrary code
on the affected system subject to the user's privileges." );
 # http://www.coresecurity.com/content/anzio-web-print-object-buffer-overflow
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41048cb7" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Aug/205" );
 script_set_attribute(attribute:"see_also", value:"http://www.anzio.com/news/newwepo.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Anzio Web Print Object 3.2.30 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/21");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
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

clsid = "{4CE8026D-5DBF-48C9-B6E9-14A2B1974A3D}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"3.2.30.0") == TRUE)
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
