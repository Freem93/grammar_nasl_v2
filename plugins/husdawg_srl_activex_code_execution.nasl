#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34491);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-4385");
  script_bugtraq_id(31752);
  script_osvdb_id(50119, 50120, 50121, 50122);
  script_xref(name:"CERT", value:"166651");
  script_xref(name:"Secunia", value:"32236");

  script_name(english:"Husdawg System Requirements Lab Multiple ActiveX Remote Code Execution");
  script_summary(english:"Checks version of affected ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that could allow
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"Instant Expert Analysis from Husdawg System Requirements Lab is
installed on the remote host.  Instant Expert Analysis software allows
websites to perform one-click software/hardware analysis of remote
systems. 

An ActiveX component used by Instant Expert Analysis can be exploited
to download and execute malicious code from an unauthorized website. 
Although, the software uses a signed Java applet to download and
execute files, it may be possible to execute code without any user
interaction if the applet is previously signed on an authorized
website. 

Reportedly either file 'sysreqlab.dll', 'sysreqlabsli.dll', or
'sysreqlab2.dll' is affected by this issue." );
 script_set_attribute(attribute:"see_also", value:"http://www.systemrequirementslab.com/bulletins/security_bulletin_1.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Husdawg System Requirements Lab 3." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Husdawg, LLC. System Requirements Lab ActiveX Unsafe Method');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/25");
 script_cvs_date("$Date: 2014/04/17 21:56:22 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

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
  "{67A5F8DC-1A4B-4D66-9F24-A704AD929EEE}",
  "{BE833F39-1E0C-468C-BA70-25AAEE55775E}",
  "{BE833F39-1E0C-468C-BA70-25AAEE55775F}"
);

info = NULL;
foreach clsid (clsids)
{
 file = activex_get_filename(clsid:clsid);

 if (file)
 {
   # Check its version.
   ver = activex_get_fileversion(clsid:clsid);

   # Current version of sysreqlab3.dll == 3.0.0.2
   if (ver && activex_check_fileversion(clsid:clsid, fix:"3.0.0.2") == TRUE)
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
  if (report_verbosity)
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
