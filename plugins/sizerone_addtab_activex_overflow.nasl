#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35327);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-4827");
  script_bugtraq_id(33148);
  script_xref(name:"OSVDB", value:"51179");
  script_xref(name:"OSVDB", value:"51184");
  script_xref(name:"Secunia", value:"32609");
  script_xref(name:"Secunia", value:"32648");
  script_xref(name:"Secunia", value:"32672");

  script_name(english:"SizerOne ActiveX Control AddTab Method Remote Buffer Overflow");
  script_summary(english:"Checks version of affected ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The SizerOne ActiveX control is installed on the remote system.  It is
included with ComponentOne Studio Enterprise as well as other
applications such as TSC2 Help Desk and SAP GUI.

The installed version of the control is affected by a heap-based
buffer overflow vulnerability that can be triggered by adding tabs
with very long captions via the control's 'AddTab()' method.  If a
remote attacker can trick a user on the affected host into viewing a
specially crafted HTML document, this issue could be leveraged to
execute arbitrary code on the affected host subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-52" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-53" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-54" );
 script_set_attribute(attribute:"solution", value:
"Update to version 8.0.20081.142 of c1sizer.ocx or 7.10 PL of
sizerone.ocx." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/09");
 script_cvs_date("$Date: 2016/12/14 20:22:12 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

clsids = make_list(
  "{24E04EBF-014D-471f-930E-7654B1193BA9}",  # ComponentOne Sizerone and TSC2 Help Desk
  "{2315B059-EDD7-4c66-933C-ECFF5B9DD593}"   # SAP GUI 6.40 and 7.10	
);

info = NULL;
foreach clsid (clsids)
{
 file = activex_get_filename(clsid:clsid);

 if (file)
 {
   # Check its version.
   ver = activex_get_fileversion(clsid:clsid);

   if ((ver && activex_check_fileversion(clsid:clsid, fix:"8.0.20081.142") == TRUE && "c1sizer.ocx" >< file ) ||
       (ver && "sizerone.ocx" >< file))
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
        "Note, though, that Nessus did not check whether the kill bit was\n",
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
        "\n",
        "Moreover, the kill bit was not set for the control(s) so they\n",
        "are accessible via Internet Explorer.\n"
      );
    }
    security_hole(port:kb_smb_transport(), extra:report);
  }	  	 
  else security_hole(kb_smb_transport());
} 
