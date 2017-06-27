#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(30202);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-0437");
  script_bugtraq_id(27384);
  script_osvdb_id(40890);

  script_name(english:"HP Virtual Rooms WebHPVCInstall.HPVirtualRooms14 ActiveX Control Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of WebHPVCInstall.HPVirtualRooms14 ActiveX control"); 
 
  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities."  );
  script_set_attribute(  attribute:"description",  value:
"The remote host contains a version of the HP Virtual Rooms
WebHPVCInstall.HPVirtualRooms14 ActiveX control that reportedly is
affected by multiple buffer overflows involving properties such as
'AuthenticationURL', 'PortalAPIURL', and 'cabroot'.  If a remote
attacker can trick a user on the affected host into visiting a
specially crafted web page, this issue could be leveraged to
execute arbitrary code on the affected host subject to the user's
privileges."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2008/Jan/452"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/487654"
  );
  script_set_attribute( attribute:"solution", value:
"Upgrade to HP Virtual Rooms v7 or use the HPVR removal tool referenced
in the vendor advisory above to remove the software."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/01/26");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:virtual_rooms");
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

info = "";
for (i=31; i>=0; i--)
{
  zeros = crap(data:"0", length:8-strlen(string(i)));
  clsid = string("{", zeros, i, "-9593-4264-8B29-930B3E4EDCCD}");

  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (
      report_paranoia > 1 ||
      activex_get_killbit(clsid:clsid) == 0
    )
    {
      info += '  ' + file + '\n';
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  report = string(
    "\n",
    "Nessus found the following affected control(s) installed :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the 'Perform thorough tests' setting was not enabled\n",
      "when this scan was run.\n"
    );
  }

  if (report_paranoia > 1)
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether the kill bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
    );
  else 
    report = string(
      report,
      "\n",
      "Moreover, the kill bit was  not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
    );
  if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
}
