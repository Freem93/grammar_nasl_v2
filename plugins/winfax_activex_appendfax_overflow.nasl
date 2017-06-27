#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38652);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2009-2570");
  script_bugtraq_id(34766);
  script_xref(name:"OSVDB", value:"54137");
  script_xref(name:"Secunia", value:"34925");

  script_name(english:"Symantec Fax Viewer Control ActiveX Control AppendFax Overflow");
  script_summary(english:"Checks for the control");
 
  script_set_attribute(  attribute:"synopsis",  value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability."  );
  script_set_attribute(  attribute:"description",   value:
"The version of the Symantec Fax Viewer Control ActiveX control, a
component included with Symantec Winfax Pro and installed on the
remote Windows host, reportedly contains a stack-based buffer overflow
that can be triggered by calling the 'AppendFax' method with an overly
long argument.  If an attacker can trick a user on the affected host
into viewing a specially crafted HTML document, he can leverage this
issue to execute arbitrary code on the affected system subject to the
user's privileges."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?1078766b"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2009/Apr/285"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2009/Apr/296"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Remove the affected software as it is no longer supported by Symantec."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/30");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
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


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = '{C05A1FBC-1413-11D1-B05F-00805F4945F6}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);

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
      "Note, though, that Nessus did not check whether the kill bit was\n",
      "set for the control's CLSID because of the Report Paranoia setting\n",
      "in effect when this scan was run.\n"
    );
  else if (activex_get_killbit(clsid:clsid) == 0)
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
    if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
    else security_hole(kb_smb_transport());
  }
}
activex_end();
