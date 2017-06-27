#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55908);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id(
    "CVE-2011-1221",
    "CVE-2011-2945",
    "CVE-2011-2946",
    "CVE-2011-2947",
    "CVE-2011-2948",
    "CVE-2011-2949",
    "CVE-2011-2950",
    "CVE-2011-2951",
    "CVE-2011-2952",
    "CVE-2011-2953",
    "CVE-2011-2954",
    "CVE-2011-2955"
  );
  script_bugtraq_id(
    49172,
    49173,
    49174,
    49175,
    49178,
    49195,
    49196,
    49198,
    49199,
    49200,
    49202,
    49996
  );
  script_osvdb_id(
    74544,
    74545,
    74546,
    74547,
    74548,
    74549,
    74551,
    74552,
    74553,
    74554,
    74555,
    76074
  );
  script_xref(name:"Secunia", value:"44014");

  script_name(english:"RealPlayer for Windows < Build 12.0.1.666 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is affected by multiple vulnerabilities :

  - A cross-zone scripting vulnerability exists in the
    RealPlayer ActiveX control and can allow injection of
    arbitrary web script or HTML in the 'Local Zone' via
    a local HTML document. (CVE-2011-1221)

  - A heap-based buffer overflow exists in SIPR.
    (CVE-2011-2945)

  - A remote code execution vulnerability exists in the
    ActiveX control. (CVE-2011-2946)

  - An unspecified cross-zone scripting remote code
    execution vulnerability exists. (CVE-2011-2947)

  - A remote code execution vulnerability exists in SWF
    DefineFont. (CVE-2011-2948)

  - A remote code execution vulnerability exists related to
    MP3 ID3 tags. (CVE-2011-2949)

  - A remote code execution vulnerability exists in QCP
    parsing. (CVE-2011-2950)

  - A remote code execution vulnerability exists in the
    Advanced Audio Coding Element. (CVE-2011-2951)

  - A use-after-free vulnerability exists relating to dialog
    boxes. (CVE-2011-2952)

  - An out-of-bounds vulnerability exists in the ActiveX
    browser plugin. (CVE-2011-2953)

  - A use-after-free vulnerability exists in Embedded
    AutoUpdate. (CVE-2011-2954)

  - A use-after-free vulnerability exists in Embedded
    Modal Dialog. (CVE-2011-2955)");

  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-265");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-266");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-267");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-268");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-269");
  # http://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=942
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d06e706e");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/08162011_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 14.0.6.666 (Build 12.0.1.666) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'RealNetworks Realplayer QCP Parsing Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/19");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

prod = get_kb_item_or_exit("SMB/RealPlayer/Product");
build = get_kb_item_or_exit("SMB/RealPlayer/Build");
path = get_kb_item("SMB/RealPlayer/Path");
version = get_kb_item("SMB/RealPlayer/Version");

vuln = FALSE;
if ("RealPlayer" == prod)
{
  if (ver_compare(ver:build, fix:'12.0.1.666') == -1) vuln = TRUE;
}
else if ("RealPlayer SP" == prod)
{
  # Check for all versions of RealPlayer SP up to and including 12.0.0.879 (version 1.1.5)
  if (build =~ '^12\\.0\\.0\\..*' && ver_compare(ver:build, fix:'12.0.0.879') <= 0) vuln = TRUE;
}
else exit(0, 'Neither RealPlayer nor RealPlayer SP was detected on the remote host.');

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Installed build   : ' + build +
      '\n  Fix               : RealPlayer Build 12.0.1.666\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'The host is not affected because '+prod+' build '+build+' is installed.');
