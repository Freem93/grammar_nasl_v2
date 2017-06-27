#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50387);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2010-2581", "CVE-2010-2582", "CVE-2010-3653", "CVE-2010-3655",
                "CVE-2010-4084", "CVE-2010-4085", "CVE-2010-4086", "CVE-2010-4087",
                "CVE-2010-4088", "CVE-2010-4089", "CVE-2010-4090");
  script_bugtraq_id(44291, 44512, 44513, 44514,
                    44515, 44516, 44517, 44518,
                    44510, 44520, 44521);
  script_osvdb_id(
    68803,
    69189,
    69191,
    69192,
    69193,
    69194,
    69195,
    69196,
    69197,
    69198,
    69208
  );
  script_xref(name:"CERT", value:"402231");
  script_xref(name:"Secunia", value:"41932");

  script_name(english:"Shockwave Player < 11.5.9.615");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser plugin that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe's Shockwave
Player that is earlier than 11.5.9.615.  Such versions are potentially
affected by the following issues :

  - A memory corruption issue exists that could lead to 
    code execution. Note that there are reports this issue
    is being exploited in the wild. (CVE-2010-3653)

  - A heap-based buffer overflow vulnerability could lead
    to code execution. (CVE-2010-2582)

  - Multiple memory corruption issues in the 'dirapi.dll'
    module could lead to code execution. (CVE-2010-2581,
    CVE-2010-3655, CVE-2010-4084, CVE-2010-4085, 
    CVE-2010-4086, CVE-2010-4088)

  - Multiple memory corruption issues in the 'IML32.dll'
    module could lead to code execution. (CVE-2010-4087,
    CVE-2010-4089)

  - A memory corruption issue that could lead to code 
    execution. (CVE-2010-4090)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-25.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.5.9.615 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Shockwave rcsL Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_apsb09_08.nasl");
  script_require_keys("SMB/shockwave_player");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

port = kb_smb_transport();
installs = get_kb_list('SMB/shockwave_player/*/path');
if (isnull(installs)) exit(0, 'Shockwave Player was not detected on the remote host.');

info = NULL;
pattern = 'SMB/shockwave_player/([^/]+)/([^/]+)/path';

foreach install (keys(installs))
{
  match = eregmatch(string:install, pattern:pattern);
  if (!match) exit(1, 'Unexpected format of KB key "' + install + '".');

  file = installs[install];
  variant = match[1];
  version = match[2];

  if (ver_compare(ver:version, fix:'11.5.9.615') == -1)
  {
    if (variant == 'Plugin')
      info += '\n  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
    else if (variant == 'ActiveX')
      info += '\n  - ActiveX control (for Internet Explorer) :\n';
    info += '    ' + file + ', ' + version + '\n';
  }
}

if (!info) exit(0, 'No vulnerable installs of Shockwave Player were found.');

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 2) s = "s";
  else s = "";

  report = 
    '\nNessus has identified the following vulnerable instance'+s+' of Shockwave'+
    '\nPlayer installed on the remote host :\n'+
    info;
  security_hole(port:port, extra:report);
}
else security_hole(port);
