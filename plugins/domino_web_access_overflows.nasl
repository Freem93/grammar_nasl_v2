#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29801);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2007-4474");
  script_bugtraq_id(26972);
  script_osvdb_id(40954);
  script_xref(name:"CERT", value:"963889");

  script_name(english:"IBM Lotus Domino Web Access ActiveX Control Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks whether the kill bit is set for Domino Web Access / iNotes6 Class controls");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the Domino Web Access or iNotes6 Class
ActiveX control, which is used by IBM Lotus Domino for uploading files
and clearing the cache on logout.

The version of this control on the remote host reportedly contains
multiple stack-based buffer overflows. If a remote attacker can trick
a user on the affected host into visiting a specially crafted web
page, this issue could be leveraged to execute arbitrary code on the
affected host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Dec/497");
  script_set_attribute(attribute:"solution", value:
"Disable use of the affected ActiveX control from within Internet
Explorer by setting its kill bit.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Lotus Domino Web Access Upload Module Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");
  script_require_ports(139, 445);
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");


# Locate files used by the control.
if (activex_init() != ACX_OK) exit(0);

info = "";
clsids = make_list(
  "{3BFFE033-BF43-11d5-A271-00A024A51325}",    #iNotes6 Class
  "{E008A543-CEFB-4559-912F-C27C2B89F13B}",    #Domino Web Access 7
  "{983A9C21-8207-4B58-BBB8-0EBC3D7C5505}"     #Domino Web Access 8
);

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
      info += '  ' + clsid + '\n' +
              '    ' + file + '\n';
    }
  }
}
activex_end();


if (info)
{
  info = string(
    "Nessus found the control(s) installed as :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    info = string(
      info,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the 'Perform thorough tests' setting was not enabled\n",
      "when this scan was run.\n"
    );
  }

  if (report_paranoia > 1)
    info = string(
      info,
      "\n",
      "Note that Nessus did not check whether the kill bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
    );
  else
    info = string(
      info,
      "\n",
      "Moreover, the kill bit was not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
    );
  security_hole(port:kb_smb_transport(), extra:info);
}
