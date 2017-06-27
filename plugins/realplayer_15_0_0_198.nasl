#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57025);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id(
    "CVE-2011-4244",
    "CVE-2011-4245",
    "CVE-2011-4246",
    "CVE-2011-4247",
    "CVE-2011-4248",
    "CVE-2011-4249",
    "CVE-2011-4250",
    "CVE-2011-4251",
    "CVE-2011-4252",
    "CVE-2011-4253",
    "CVE-2011-4254",
    "CVE-2011-4255",
    "CVE-2011-4256",
    "CVE-2011-4257",
    "CVE-2011-4258",
    "CVE-2011-4259",
    "CVE-2011-4260",
    "CVE-2011-4261",
    "CVE-2011-4262"
  );
  script_bugtraq_id(50741);
  script_osvdb_id(
    77268,
    77269,
    77270,
    77271,
    77272,
    77273,
    77274,
    77275,
    77276,
    77277,
    77278,
    77279,
    77280,
    77281,
    77282,
    77283,
    77284,
    77285,
    77286
  );

  script_name(english:"RealPlayer for Windows < 15.0.0 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is earlier than 15.0.0.  As such, it is
affected by multiple vulnerabilities :

  - A head-based buffer overflow exists in the 'RealVideo'
    renderer. (CVE-2011-4244)

  - Memory corruption errors exist in the 'RealVideo'
    renderer and the 'AAC' codec. (CVE-2011-4245,
    CVE-2011-4246)

  - Remote code execution is possible due to errors related
    to 'QCELP' parsing. (CVE-2011-4247)

  - Remote code execution is possible due to errors related
    to 'AAC' file parsing. (CVE-2011-4248)

  - Remote code execution is possible due to errors related
    to improper handling of indexes in 'RV30' encoded files.
    (CVE-2011-4249)

  - Remote code execution is possible due to errors related
    to 'ATRC' file parsing. (CVE-2011-4250)

  - Remote code execution is possible due to errors related
    to 'RealAudio' 'Sample Size' parsing. (CVE-2011-4251)

  - Remote code execution is possible due to errors related
    to 'RV10' decoding. (CVE-2011-4252)

  - Remote code execution is possible due to errors related
    to 'RV20' decoding. (CVE-2011-4253) 

  - Remote code execution is possible due to errors related
    to 'RTSP' 'SETUP' requests (CVE-2011-4254)

  - Remote code execution is possible due to errors related
    to improper handling of invalid codec names. 
    (CVE-2011-4255)

  - Remote code execution is possible due to errors related
    to uninitialized indexes in 'RV30' files. 
    (CVE-2011-4256)

  - Remote code execution is possible due to errors related
    to 'Cook' codec channel parsing. (CVE-2011-4257)

  - Remote code execution is possible due to errors related
    to 'IVR MLTI' chunk length parsing. (CVE-2011-4258)

  - An integer underflow error exists related to 'MPG'
    width handling. (CVE-2011-4259)

  - Remote code execution is possible due to errors related
    to improper handling of malformed 'MP4' headers and 
    parsing of 'MP4' files in general.
    (CVE-2011-4260, CVE-2011-4262)

  - A heap corruption error exists related to improper
    handling of 'MP4' video dimensions. (CVE-2011-4261)");

  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-331");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-332");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-333");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-334");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-335");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-336");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-337");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-338");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-046");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-050");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-051");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-053/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-085/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-087/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-092/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Jun/73");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Jun/75");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523067/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/11182011_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 15.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");

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
  if (ver_compare(ver:build, fix:'15.0.0.0') == -1) vuln = TRUE;
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
      '\n  Fixed version     : RealPlayer 15.0\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'The '+prod+' build '+build+' install on the host is not affected.');
