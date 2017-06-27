#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25799);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-4031", "CVE-2007-4061", "CVE-2007-4062");
  script_bugtraq_id(25088);
  script_xref(name:"EDB-ID", value:"4230");
  script_xref(name:"EDB-ID", value:"4237");
  script_xref(name:"OSVDB", value:"37702");
  script_xref(name:"OSVDB", value:"37703");
  script_xref(name:"OSVDB", value:"37704");

  script_name(english:"Nessus Windows < 3.0.6.1 ScanCtrl ActiveX Multiple Method File Manipulation");
  script_summary(english:"Checks versions of ScanCtrl ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the ScanCtrl ActiveX control, a part of
Nessus for Windows.

The version of the ScanCtrl ActiveX control, installed as part of
Nessus for Windows on the remote host, fails to validate input to
several methods. If an attacker can trick a user on the affected host
into visiting a specially crafted web page, this issue could be
leveraged to delete or write to arbitrary files or even execute
arbitrary code on the host subject to the user's privileges." );

 script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus for Windows version 3.0.6.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/28");
 script_cvs_date("$Date: 2017/02/23 16:41:17 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate files used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{A47D5315-321D-4DEE-9DB3-18438023193B}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"3.0.6.321") == TRUE)
  {
    report = string(
      "Version '", ver, "' of the vulnerable control is installed as :\n",
      "\n",
      "  ", file
      );
    security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
