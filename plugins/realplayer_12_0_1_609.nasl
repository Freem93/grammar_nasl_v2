#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50612);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id(
    "CVE-2010-0121", "CVE-2010-0125", "CVE-2010-2579", "CVE-2010-2997", 
    "CVE-2010-2999", "CVE-2010-4375", "CVE-2010-4376", "CVE-2010-4377", 
    "CVE-2010-4378", "CVE-2010-4379", "CVE-2010-4380", "CVE-2010-4381", 
    "CVE-2010-4382", "CVE-2010-4383", "CVE-2010-4384", "CVE-2010-4385", 
    "CVE-2010-4386", "CVE-2010-4387", "CVE-2010-4388", "CVE-2010-4389", 
    "CVE-2010-4390", "CVE-2010-4391", "CVE-2010-4392", "CVE-2010-4394", 
    "CVE-2010-4395", "CVE-2010-4396", "CVE-2010-4397"
  );
  script_bugtraq_id(
    44847, 45406, 45407, 45409, 45410, 45411, 45412, 45414,
    45421, 45422, 45424, 45425, 45426, 45428, 45429,
    45444, 45445, 45448, 45449, 45451, 45452, 45453, 45455,
    45458, 45459, 45463, 45464, 45465
  );
  script_osvdb_id(
    69831,
    69832,
    69833,
    69834,
    69835,
    69836,
    69837,
    69838,
    69839,
    69840,
    69841,
    69842,
    69843,
    69844,
    69845,
    69846,
    69847,
    69848,
    69849,
    69850,
    69851,
    69852,
    69853,
    69854,
    69855,
    69856,
    69857,
    69858,
    69859
  );
  script_xref(name:"Secunia", value:"38550");
  script_xref(name:"Secunia", value:"42203");

  script_name(english:"RealPlayer for Windows < Build 12.0.1.609 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is affected by multiple vulnerabilities:

  - An error in the 'Cook' codec initialization function 
    and can be used to access uninitialized memory. 
    (CVE-2010-0121)

  - Freed pointer access in the handling of the 'Stream 
    Title' tag in a SHOUTcast stream using the ICY protocol.
    (CVE-2010-2997)

  - An integer overflow error exists when handling a 
    malformed 'MLLT atom' in an AAC file. (CVE-2010-2999)

  - Heap-based buffer overflow when handling of multi-rate 
    audio streams. (CVE-2010-4375)

  - Heap-based buffer overflow when parsing GIF87a files
    with large 'Screen Width' values in the 'Screen 
    Descriptor' header over RTSP. (CVE-2010-4376)

  - Heap-based buffer overflow when parsing of 'Cook' codec
    information in a Real Audio file with many subbands.
    (CVE-2010-4377)

  - Memory corruption in parsing of a 'RV20' video stream.
    (CVE-2010-4378)

  - Heap-based buffer overflow when parsing 'AAC', 'IVR', 
    'RealMedia', 'RA5', 'RealPix', 'SIPR' and 'SOUND' files.
    (CVE-2010-0125, CVE-2010-4379, CVE-2010-4380, 
     CVE-2010-4381, CVE-2010-4382, CVE-2010-4383, 
     CVE-2010-4384, CVE-2010-4386, CVE-2010-4387, 
     CVE-2010-4390, CVE-2010-4391, CVE-2010-4392)

  - Integer overflow in the handling of frame dimensions in
    a 'SIPR' stream. (CVE-2010-4385)

  - An input validation error in the 'pnen3260.dll' module 
    can allow arbitrary code execution via a crafted 'TIT2 
    atom' in an AAC file. (CVE-2010-4397)

  - Heap-based buffer overflow in the 'Cook' codec handling 
    functions. (CVE-2010-2579, CVE-2010-4389)

  - Heap-based buffer overflow in the decoding portion of 
    the 'Advanced Audio Coding' compression implementation. 
    (CVE-2010-4395)

  - Cross-site scripting in ActiveX control and several
    HTML files. (CVE-2010-4396, CVE-2010-4388)"
  );

  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 14.0.1.609 (Build 12.0.1.609) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-266/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-267/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-268/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-269/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-270/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-271/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-272/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-273/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-274/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-275/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-276/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-277/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-278/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-279/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-280/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-281/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-282/");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/16");
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
build = get_kb_item_or_exit("SMB/RealPlayer/Build");
path = get_kb_item("SMB/RealPlayer/Path");

vuln = FALSE;
if ("RealPlayer" == prod)
{
  if (
    build =~ '^6\\.0\\.14\\..*' ||
    (build =~ '^12\\.0\\.1\\..*' && ver_compare(ver:build, fix:'12.0.1.609') == -1)
  ) vuln = TRUE;
}
else if ("RealPlayer SP" == prod)
{
  build_arr = split(build, sep:'.', keep:FALSE);
  for (i=0; i<max_index(build_arr); i++)
    build_arr[i] = int(build_arr[i]);

  if (build_arr[0] == 12 && build_arr[1] == 0 && build_arr[2] == 0 && build_arr[3] <= 879) vuln = TRUE;
}
else exit(0, 'Neither RealPlayer nor RealPlayer SP was detected on the remote host.');

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Product         : ' + prod +
      '\n  Path            : ' + path +
      '\n  Installed build : ' + build +
      '\n  Fix             : RealPlayer Build 12.0.1.609\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'The host is not affected because '+prod+' build '+build+' is installed.');
