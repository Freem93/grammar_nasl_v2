#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50022);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/02/14 17:23:21 $");

  script_cve_id(
    "CVE-2010-2578",
    "CVE-2010-3747",
    "CVE-2010-3748",
    "CVE-2010-3750"
  );
  script_bugtraq_id(44441, 44442, 44444, 44450);
  script_osvdb_id(68671, 68673, 68674, 68676);
  script_xref(name:"EDB-ID", value:"15991");
  script_xref(name:"EDB-ID", value:"16998");
  script_xref(name:"MSVR", value:"MSVR11-004");
  script_xref(name:"Secunia", value:"41743");

  script_name(english:"RealPlayer Enterprise for Windows < Build 6.0.12.1823 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer Enterprise build number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host has multiple buffer overflow vulnerabilities :

  - A 'QCP' parsing heap-based buffer overflow vulnerability
    exists. (CVE-2010-2578)

  - An uninitialized pointer vulnerability exists in the
    CDDA URI ActiveX control. (CVE-2010-3747)

  - A stack overflow vulnerability exists in the RichFX 
    component. (CVE-2010-3748)

  - A parameter injection vulnerability exists in the
    RecordClip browser extension. (CVE-2010-3749)

  - A remote code execution vulnerability exists in 
    RJMDSections. (CVE-2010-3750)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-210");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-212");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-213");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/10152010_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer Enterprise 2.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'RealNetworks RealPlayer CDDA URI Initialization Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

prod  = get_kb_item_or_exit('SMB/RealPlayer/Product');
build = get_kb_item_or_exit('SMB/RealPlayer/Build');
version = get_kb_item('SMB/RealPlayer/Version');

if ("RealPlayer Enterprise" == prod)
{
  if (ver_compare(ver:build, fix:'6.0.11.0') >= 0 && ver_compare(ver:build, fix:'6.0.12.1823') == -1)
  {
    if (report_verbosity > 0)
    {
      path = get_kb_item("SMB/RealPlayer/Path");
      if (isnull(path)) path = 'n/a';

      report = '\n  Product         : ' + prod;
      if (!isnull(version)) report += '\n  Version         : ' + version;
      report +=
        '\n  Path            : ' + path +
        '\n  Installed build : ' + build +
        '\n  Fixed build     : 6.0.12.1823\n';
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(get_kb_item("SMB/transport"));
    exit(0);
  }
  else exit(0, 'The host is not affected because RealPlayer Enterprise build '+build+' is installed.');
}
else exit(0, "RealPlayer Enterprise was not detected on the remote host.");
