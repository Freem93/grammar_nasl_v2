#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33859);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2008-3558");
  script_bugtraq_id(30578);
  script_osvdb_id(47344);
  script_xref(name:"Secunia", value:"31397");

  script_name(english:"WebEx Meeting Manager WebexUCFObject ActiveX Control Buffer Overflow");
  script_summary(english:"Checks version of atucfobj control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The atucfobj module of the WebexUCFObject ActiveX control, used by
WebEx Meeting Manager and installed on the remote host, reportedly
contains a stack-based buffer overflow in its 'NewObject()' method.
If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, this method could be used to execute
arbitrary code on the affected system, subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Aug/83" );
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20080814-webex
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63ee1aec" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Aug/322" );
 script_set_attribute(attribute:"solution", value:
"One solution is to confirm that the WebEx Meeting Service is running a
fixed version of the software based on the instructions in Cisco's
advisory, join a meeting or manually update the Meeting Manager
client, and ensure that version 20.2008.2606.4919 of the control
itself is installed.

Another is to remove the software as described in Cisco's advisory.

A third is to set the control's kill bit, again, as described in
Cisco's advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'WebEx UCF atucfobj.dll ActiveX NewObject Method Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/11");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
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

clsid = "{32E26FD9-F435-4A20-A561-35D4B987CFDC}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"20.2008.2606.4919") == TRUE)
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
