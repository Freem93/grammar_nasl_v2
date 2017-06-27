#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40666);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/04/21 21:40:26 $");

  script_cve_id("CVE-2009-2627");
  script_bugtraq_id(36068);
  script_osvdb_id(57201);
  script_xref(name:"CERT", value:"485961");
  script_xref(name:"Secunia", value:"36343");

  script_name(english:"Acer AcerCtrls.APlunch ActiveX Arbitrary Command Execution");
  script_summary(english:"Checks for the ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows arbitrary
code execution.");
  script_set_attribute(attribute:"description", value:
"The remote host contains an ActiveX control from Acer called
'AcerCtrls.APlunch'.  If this control is distributed with the
appropriate 'Implemented Categories' registry key, it may be marked as
safe for scripting.  This would allow a web page in Internet Explorer to
call the control's 'Run()' method.  A remote attacker could exploit this
by tricking a user into visiting a malicious web page that executes
arbitrary commands. 

Please note this vulnerability is similar to, but different from
CVE-2006-6121.  This control has different parameters and uses a
different CLSID.");
  script_set_attribute(attribute:"solution", value:
"No patch is available at this time.  Disable this ActiveX control by
setting the kill bit for the related CLSID.  Refer to the CERT advisory
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
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


if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The 'SMB/Registry/Enumerated' KB item is missing");

# Locate the file used by the controls.
if (activex_init() != ACX_OK)
   exit(1, "activex_init() failed.");

clsid = "{3895DD35-7573-11D2-8FED-00606730D3AA}";
file = activex_get_filename(clsid:clsid);
if (!file)
{
  activex_end();
  if (isnull(file)) exit(1, "activex_get_filename() returned NULL.");
  else exit(0, "The AcerCtrls.APlunch control is not installed.");
}

# Acer hasn't released a patch yet.  All we can do for now is check to see
# if the kill bit is set.
if (activex_get_killbit(clsid:clsid) == 0)
{
  if (report_verbosity > 0)
  {
    version = activex_get_fileversion(clsid:clsid);
    if (!version) version = "Unknown";

    report = string(
      "\n",
      "The kill bit is not set for the following control :\n\n",
      "  Class Identifier : ", clsid, "\n",
      "  Filename         : ", file, "\n",
      "  Version          : ", version, "\n"
    );

    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(port:kb_smb_transport());
  
  exit (0);
}
else exit(0, "The system is not affected.");

