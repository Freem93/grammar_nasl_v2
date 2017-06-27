#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80176);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/23 13:47:46 $");

  script_cve_id(
    "CVE-2011-0317",
    "CVE-2011-0318",
    "CVE-2011-0319",
    "CVE-2011-0320",
    "CVE-2011-0335",
    "CVE-2011-2108",
    "CVE-2011-2109",
    "CVE-2011-2111",
    "CVE-2011-2112",
    "CVE-2011-2113",
    "CVE-2011-2114",
    "CVE-2011-2115",
    "CVE-2011-2116",
    "CVE-2011-2117",
    "CVE-2011-2118",
    "CVE-2011-2119",
    "CVE-2011-2120",
    "CVE-2011-2121",
    "CVE-2011-2122",
    "CVE-2011-2124",
    "CVE-2011-2125",
    "CVE-2011-2126",
    "CVE-2011-2127",
    "CVE-2011-2128"
  );
  script_bugtraq_id(
    48273,
    48275,
    48278,
    48284,
    48286,
    48287,
    48288,
    48289,
    48290,
    48291,
    48292,
    48294,
    48296,
    48297,
    48298,
    48299,
    48300,
    48302,
    48304,
    48306,
    48307,
    48308,
    48309,
    48310,
    48311
  );
  script_osvdb_id(
    73010,
    73011,
    73012,
    73013,
    73014,
    73015,
    73016,
    73017,
    73018,
    73019,
    73020,
    73021,
    73022,
    73023,
    73024,
    73025,
    73026,
    73027,
    73028,
    73029,
    73030,
    73031,
    73032,
    73033,
    73034,
    88222
  );

  script_name(english:"Adobe Shockwave Player <= 11.5.9.620 (APSB11-17) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.5.9.620 or earlier. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption vulnerabilities affect the
    'Dirapi.dll' component that can result in arbitrary code
    execution. (CVE-2011-0317, CVE-2011-0318, CVE-2011-0319,
    CVE-2011-0320, CVE-2011-2119, CVE-2011-0335,
    CVE-2011-2122)

  - An arbitrary code execution vulnerability occurs due to
    an unspecified design flaw. (CVE-2011-2108)

  - Multiple integer overflow vulnerabilities affect the
    'Dirapi.dll' component that can result in arbitrary code
    execution. (CVE-2011-2109)

  - Multiple memory corruption vulnerabilities affect the
    'IML32.dll' component that can result in arbitrary code
    execution. (CVE-2011-2111, CVE-2011-2115, CVE-2011-2116)

  - Multiple buffer overflow vulnerabilities affect the
    'IML32.dll' component that can result in arbitrary code
    execution. (CVE-2011-2112)

  - Multiple buffer overflow vulnerabilities affect the
    'Shockwave3DAsset' component that can result in
    arbitrary code execution. (CVE-2011-2113)

  - Multiple unspecified memory corruption vulnerabilities
    can result in arbitrary code execution. (CVE-2011-2114,
    CVE-2011-2117, CVE-2011-2124, CVE-2011-2127,
    CVE-2011-2128)

  - An input validation vulnerability affects the 'FLV ASSET
    Xtra' component that can result in arbitrary code
    execution. (CVE-2011-2118)

  - An integer overflow vulnerability affects the
    'CursorAsset x32' component that can result in arbitrary
    code execution. (CVE-2011-2120)

  - An unspecified integer overflow vulnerability can result
    in arbitrary code execution. (CVE-2011-2121)

  - An integer overflow vulnerability affects the 'Shockwave
    3D Asset x32' component that can result in arbitrary
    code execution. (CVE-2011-2123)

  - A buffer overflow vulnerability affects the
    'Dirapix.dll' component that can result in arbitrary
    code execution. (CVE-2011-2125)

  - An unspecified buffer overflow vulnerability can result
    in arbitrary code execution. (CVE-2011-2126)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-200/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-201/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-202/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-203/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-204/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-205/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-206/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-207/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-208/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-209/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-210/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-211/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-212/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-213/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-214/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-215/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-216/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-217/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-041/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-17.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.6.0.626 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_detect_macosx.nbin");
  script_require_keys("installed_sw/Shockwave Player", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = 'Shockwave Player';

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver = install['version'];
path = install['path'];

if (ver_compare(ver:ver, fix:'11.5.9.620', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.6.0.626' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
