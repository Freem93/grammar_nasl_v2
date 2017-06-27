#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57863);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id(
    "CVE-2012-0922",
    "CVE-2012-0923",
    "CVE-2012-0924",
    "CVE-2012-0925",
    "CVE-2012-0926",
    "CVE-2012-0927",
    "CVE-2012-0928"
  );
  script_bugtraq_id(51883, 51884, 51885, 51887, 51888, 51889, 51890);
  script_osvdb_id(78909, 78910, 78911, 78912, 78913, 78914, 78915);

  script_name(english:"RealPlayer for Windows < 15.0.2.71 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is earlier than 15.0.2.71.  As such, it is
affected by multiple vulnerabilities :

  - Errors exist related to 'rvrender RMFF' flags, 'RV20' 
    frame size arrays, 'VIDOBJ_START_CODE', 'RV40', 'RV10',
    'coded_frame_size' and 'Atrac' sample decoding and can
    result in remote, arbitrary code execution. 
    (CVE-2012-0922, CVE-2012-0923, CVE-2012-0924, 
    CVE-2012-0925, CVE-2012-0926, CVE-2012-0927, 
    CVE-2012-0928)");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-048/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-049/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-084/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-086/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-183/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-187/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-195/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Jun/72");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Jun/74");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Nov/109");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Nov/134");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/02062012_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 15.0.2.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/08");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
  if (ver_compare(ver:build, fix:'15.0.2.71') == -1) vuln = TRUE;
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
      '\n  Fixed version     : RealPlayer 15.0.2.71\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'The '+prod+' build '+build+' install on the host is not affected.');
