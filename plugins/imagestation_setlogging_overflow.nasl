#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33484);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-0748");
  script_bugtraq_id(27715);
  script_osvdb_id(41601);
  script_xref(name:"EDB-ID", value:"5086");
  script_xref(name:"Secunia", value:"28854");

  script_name(english:"Sony ImageStation AxRUploadServer.AxRUploadControl ActiveX (AxRUploadServer.dll) SetLogging Method Overflow");
  script_summary(english:"Checks version of ImageStation AxRUploadServer.AxRUploadControl.1 control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the AxRUploadServer.AxRUploadControl.1
ActiveX control, which was used to upload photos to Sony's
ImageStation photo sharing and printing service.

The version of this control installed on the remote host reportedly
contains a buffer overflow when handling a long argument to the
'SetLogging' method.  If an attacker can trick a user on the affected
host into viewing a specially crafted HTML document, this method
could be used to execute arbitrary code on the affected system subject
to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/487802/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Remove the affected control as the ImageStation service was shut down
in February 2008." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/15");
 script_cvs_date("$Date: 2016/05/20 14:03:01 $");
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

clsid = "{E9A7F56F-C40F-4928-8C6F-7A72F2A25222}";
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
      "and uses the following CLSID :\n",
      "\n",
      "  ", clsid, "\n",
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
      "and uses the following CLSID :\n",
      "\n",
      "  ", clsid, "\n",
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
