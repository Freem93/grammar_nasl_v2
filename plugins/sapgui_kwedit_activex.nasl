#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36163);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-4830");
  script_bugtraq_id(34524);
  script_xref(name:"Secunia", value:"32869");
  script_xref(name:"OSVDB", value:"53680");

  script_name(english:"SAP GUI KWEdit ActiveX Control SaveDocumentAs() Insecure Method");
  script_summary(english:"Checks for control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
remote code execution vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of the KWEdit ActiveX control on the remote host is
reportedly affected by a remote code execution vulnerability. The
control provides the insecure method 'SaveDocumentAs()', which saves
an HTML document to a specified location. This can be exploited in
combination with e.g. the 'OpenDocument()' method to disclose file
contents or to execute arbitrary code on the affected host subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-56/" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version and verify the kill bit is set." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'EnjoySAP SAP GUI ActiveX Control Arbitrary File Download');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/15");
 script_cvs_date("$Date: 2014/04/17 18:47:27 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:sap_gui");
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Locate the file used by the controls
if (activex_init() != ACX_OK) exit(0);

clsid = '{2137278D-EF5C-11D3-96CE-0004AC965257}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_filename(clsid:clsid);

  if (ver) ver = string("Version ", ver);
  else ver = string("An unknown version");

  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "\n",
      ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the kill bit was \n",
      "set for the control's CLSID because the Report Paranoia setting \n",
      "was in effect when this scan was run.\n"
    );
  else if(activex_get_killbit(clsid:clsid) == 0)
    report = string(
      "\n",
      ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Moreover, its kill bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );
  if (report)
  {
    if (report_verbosity > 0)
      security_hole(port:kb_smb_transport(), extra:report);
    else
      security_hole(kb_smb_transport());
  }
}
activex_end();
