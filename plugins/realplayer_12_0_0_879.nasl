#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48907);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id(
    "CVE-2010-0116",
    "CVE-2010-0117",
    "CVE-2010-0120",
    "CVE-2010-2578",
    "CVE-2010-2996",
    "CVE-2010-2998",
    "CVE-2010-3000",
    "CVE-2010-3001",
    "CVE-2010-3002",
    "CVE-2010-3747",
    "CVE-2010-3748",
    "CVE-2010-3749",
    "CVE-2010-3750",
    "CVE-2010-3751"
  );
  script_bugtraq_id(
    42775,
    44423,
    44440,
    44441,
    44442,
    44443,
    44444,
    44450
  );
  script_osvdb_id(
    67730,
    67731,
    67732,
    67733,
    67734,
    67735,
    67736,
    68671,
    68672,
    68673,
    68674,
    68675,
    68676,
    68677
  );
  script_xref(name:"EDB-ID", value:"15991");
  script_xref(name:"EDB-ID", value:"16998");
  script_xref(name:"MSVR", value:"MSVR11-004");
  script_xref(name:"Secunia", value:"41096");
  script_xref(name:"Secunia", value:"41154");

  script_name(english:"RealPlayer for Windows < Build 12.0.0.879 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by multiple 
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host has multiple buffer overflow vulnerabilities :

  - A RealPlayer malformed 'IVR' pointer index code 
    execution vulnerability exists. 
    (CVE-2010-2996, CVE-2010-2998)

  - A RealPlayerActiveX unauthorized file access 
    vulnerability exists. (CVE-2010-3002)

  - A RealPlayer 'QCP' file parsing integer overflow
    vulnerability exists. (CVE-2010-0116)

  - A vulnerability exists in the way RealPlayer processes
    the dimensions in the 'YUV420' transformation of 'MP4' 
    content. (CVE-2010-0117)

  - A heap-based buffer overflow vulnerability exists in
    RealPlayer's 'QCP' parsing. (CVE-2010-0120)

  - A vulnerability exists in the ActiveX IE plugin relating
    to the opening of multiple browser windows. 
    (CVE-2010-3001)

  - Multiple integer overflow vulnerabilities exist in
    RealPlayer's 'FLV' parsing. (CVE-2010-3000)
    
  - An uninitialized pointer vulnerability exists in the
    CDDA URI ActiveX Control. (CVE-2010-3747)
    
  - A remote code execution vulnerability exists in 
    RJMDSections. (CVE-2010-3750)
    
  - A RealPlayer 'QCP' parsing heap-based buffer overflow
    vulnerability exists. (CVE-2010-2578)

  - A remote code execution issue exists in multiple 
    protocol handlers for the RealPlayer ActiveX control.
    (CVE-2010-3751)

  - A stack overflow vulnerability exists in the RichFX
    component. (CVE-2010-3748)

  - A parameter injection vulnerability exists in the
    RecordClip browser extension. (CVE-2010-3749)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-166");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-167");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-209");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-210");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-211");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-212");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-213");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-8/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-3/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-5/");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/08262010_player/en/");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/10152010_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer SP 1.1.5 or later.");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

prod = get_kb_item_or_exit("SMB/RealPlayer/Product");
build= get_kb_item_or_exit("SMB/RealPlayer/Build");

vuln = FALSE;
if ("RealPlayer" == prod)
{
  if (build =~ '^6\\.0\\.14\\..*') vuln = TRUE;
}
if ("RealPlayer SP" == prod)
{
  if (build =~ '^12\\..*' && ver_compare(ver:build, fix:'12.0.0.879') == -1) vuln = TRUE;
}

if ("RealPlayer" == prod || "RealPlayer SP" == prod)
{
  if (vuln)
  {
    if (report_verbosity > 0)
    {
      if ("RealPlayer SP" == prod)
        report =
          '\n  Product         : ' + prod +
          '\n  Installed build : ' + build +
          '\n  Fixed build     : 12.0.0.879\n';
      else if ("RealPlayer" == prod)
        report =
          '\n  Product         : ' + prod +
          '\n  Installed build : ' + build +
          '\n  Fix             : RealPlayer SP 1.1.5\n';

      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(get_kb_item("SMB/transport"));
    exit(0);
  }
  else exit(0, 'The host is not affected because '+prod+' build '+build+' is installed.');
}
else exit(0, "Neither RealPlayer nor RealPlayer SP was detected on the remote host.");
