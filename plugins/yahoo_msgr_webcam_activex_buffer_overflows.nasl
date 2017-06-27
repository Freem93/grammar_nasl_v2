#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25459);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/01 20:05:52 $");

  script_cve_id("CVE-2007-3147", "CVE-2007-3148");
  script_bugtraq_id(24354, 24355);
  script_osvdb_id(37081, 37082);

  script_name(english:"Yahoo! Messenger Webcam ActiveX Buffer Overflows");
  script_summary(english:"Checks versions of Webcam ActiveX controls");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a least one ActiveX control that is
affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the 'Webcam' ActiveX controls included with
Yahoo! Messenger.

The version of at least one of these controls on the remote host has a
buffer overflow.  If an attacker can trick a user on the affected host
into visiting a specially crafted web page, this issue could be
leveraged to execute arbitrary code on the host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jun/131");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jun/133");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/470861/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://messenger.yahoo.com/security_update.php?id=060707");
  script_set_attribute(attribute:"solution", value:
"Update to the latest version of Yahoo! Messenger and ensure that the
version of both affected controls is 2.0.1.6 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Yahoo! Messenger 8.1.0.249 ActiveX Control Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:yahoo:messenger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate files used by the controls.
if (activex_init() != ACX_OK) exit(0);

info = "";
clsids = make_list(
  "{DCE2F8B1-A520-11D4-8FD0-00D0B7730277}",
  "{9D39223E-AE8E-11D4-8FD3-00D0B7730277}"
);
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    ver = activex_get_fileversion(clsid:clsid);
    if (ver && activex_check_fileversion(clsid:clsid, fix:"2.0.1.6") == TRUE)
    {
      info += '  ' + file + ' (' + ver + ')\n';
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  report = string(
    "Nessus found the following affected control(s) installed :\n",
    "\n",
    info
  );
  security_hole(port:kb_smb_transport(), extra: report);
}
