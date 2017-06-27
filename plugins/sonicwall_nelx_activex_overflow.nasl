#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27618);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-5603", "CVE-2007-5814");
  script_bugtraq_id(26288);
  script_osvdb_id(39069, 40893);
  script_xref(name:"CERT", value:"298521");

  script_name(english:"SonicWALL SSL-VPN NetExtender NELaunchCtrl ActiveX Control Multiple Overflows");
  script_summary(english:"Checks version of NELaunchCtrl ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the 'NELaunchCtrl' ActiveX control included
with the SonicWALL NetExtender VPN client software. 

The version of this control installed on the remote host fails to
validate arguments to several methods, such as 'AddRouteEntry',
'serverAddress', 'sessionId', 'clientIPLower', etc.  If a remote
attacker can trick a user on the affected host into visiting a
specially crafted web page, the attacker could leverage these issues 
to overflow a buffer and execute arbitrary code on the host subject to
the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483097/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Nov/12");
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.1.0.51 / 2.5.0.56 or later of the control." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'SonicWall SSL-VPN NetExtender ActiveX Control Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/11/01");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:sonicwall:ssl_vpn");
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


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{6EEFD7B1-B26C-440D-B55A-1EC677189F30}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (
    ver && 
    (
      ver =~ "^[01]\." ||
      (
        ver =~ "^2\.1\." && 
        activex_check_fileversion(clsid:clsid, fix:"2.1.0.51") == TRUE
      ) ||
      (
        ver =~ "^2\.5\." && 
        activex_check_fileversion(clsid:clsid, fix:"2.5.0.56") == TRUE
      )
    )
  )
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
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
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its kill bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
