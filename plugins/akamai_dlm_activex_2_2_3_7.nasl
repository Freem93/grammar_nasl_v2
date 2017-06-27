#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33102);
  script_version("$Revision: 1.15 $");
script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2008-1770");
  script_xref(name:"EDB-ID", value:"5741");
  script_xref(name:"Secunia", value:"30537");
  script_xref(name:"OSVDB", value:"45968");

  script_name(english:"Akamai Download Manager ActiveX Control < 2.2.3.6 Arbitrary File Download");
  script_summary(english:"Checks version of Download Manager ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows arbitrary
file downloads." );
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains the Download Manager ActiveX control
from Akamai, which helps users download content.

The version of this ActiveX control on the remote host reportedly is
affected by a parameter injection vulnerability that could be
exploited to download arbitrary files and place them in arbitrary
locations on the affected host, such as the 'Startup' folder used by
Windows.  If an attacker can trick a user on the affected host into
visiting a specially crafted web page, this method could be used to
execute arbitrary code on the affected system subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jun/59" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493077/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.2.3.7 or later of the control." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/05");
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
if (activex_init() != ACX_OK) 
  exit(1, "ActiveX initialization failed.");

clsids = make_list("{4871A87A-BFDD-4106-8153-FFDE2BAC2967}",
                   "{FFBB3F3B-0A5A-4106-BE53-DFE1E2340CB1}",
                   "{2AF5BD25-90C5-4EEC-88C5-B44DC2905D8B}");

info = NULL;
foreach clsid (clsids)
{
 file = activex_get_filename(clsid:clsid);

 if (file)
 {
   # Check its version.
   ver = activex_get_fileversion(clsid:clsid);

   # Fixed version of DownloadManagerV2.ocx == 2.2.3.7
   if (ver && activex_check_fileversion(clsid:clsid, fix:"2.2.3.7") == TRUE)
    {
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
       {
        info += '  - ' + clsid + '\n' +
                '    ' + file + ', ' + ver + '\n';

         if (!thorough_tests) break;
       } 
    }
  }
}

activex_end();

if (info)
{
  if (report_verbosity > 0)
  {
    if (report_paranoia > 1)	
    {
      report = string(
        "\n",
     	"Nessus found the following affected control(s) installed :\n",
     	"\n",
    	info,
      	"\n",
        "Note that Nessus did not check whether the kill bit was set for\n",
        "the control(s) because of the Report Paranoia setting in effect\n",
        "when this scan was run.\n"
      );
    }
    else
    {
      report = string(
        "\n",
        "Nessus found the following affected control(s) installed :\n",
        "\n",
        info,
        "\n",
        "Moreover, the kill bit was  not set for the control(s) so they\n",
        "are accessible via Internet Explorer.\n"
      );
    }
    security_hole(port:kb_smb_transport(), extra:report);
  }	  	 
  else security_hole(kb_smb_transport());
} 
