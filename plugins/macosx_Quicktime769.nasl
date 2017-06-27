#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(51061);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2012/02/06 21:20:15 $");

  script_cve_id(
    "CVE-2010-3787",
    "CVE-2010-3788",
    "CVE-2010-3789",
    "CVE-2010-3790",
    "CVE-2010-3791",
    "CVE-2010-3792",
    "CVE-2010-3793",
    "CVE-2010-3794",
    "CVE-2010-3795",
    "CVE-2010-3800",
    "CVE-2010-3801",
    "CVE-2010-3802",
    "CVE-2010-4009"
  );
  script_bugtraq_id(
    44785,
    44787,
    44789,
    44790,
    44792,
    44794,
    44795,
    44796,
    44798,
    45236,
    45239,
    45240, 
    45241
  );
  script_osvdb_id(
    69152,
    69313,
    69314,
    69315,
    69316,
    69317,
    69318,
    69319,
    69320,
    69754,
    69755,
    69756,
    69757
  );

  script_name(english:"QuickTime < 7.6.9 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.6.9.  Such versions contain several vulnerabilities :

  - A heap buffer overflow in QuickTime's handling of JP2
    images may lead to an application crash or arbitrary 
    code execution. (CVE-2010-3787)

  - Uninitialized memory access issues in QuickTime's 
    handling of JP2, FlashPix, and GIF images may lead to 
    an application crash or arbitrary code execution. 
    (CVE-2010-3788, CVE-2010-3794, CVE-2010-3795)

  - Memory corruption issues in QuickTime's handling of
    AVI files, movie files, Sorenson encoded movie files, 
    PICT files, FlashPix images, and panorama atoms in QTVR
    (QuickTime Virtual Reality) movie files may lead to an
    application crash or arbitrary code execution. 
    (CVE-2010-3789, CVE-2010-3790, CVE-2010-3793, 
    CVE-2010-3800, CVE-2010-3801, CVE-2010-3802)

  - A buffer overflow in QuickTime's handling of MPEG-
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-3791)

  - A signedness issue in QuickTime's handling of MPEG-
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-3792)

  - An integer overflow in QuickTime's handling of movie
    files may lead to an application crash or arbitrary 
    code execution. (CVE-2010-4009)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4447"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Dec/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to QuickTime 7.6.9 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("macosx_Quicktime652.nasl", "ssh_get_info.nasl");
  script_require_keys("MacOSX/QuickTime/Version", "Host/uname");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


uname = get_kb_item_or_exit("Host/uname");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");

darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (!ereg(pattern:"^9\.[0-8]\.", string:darwin))
  exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");


version = get_kb_item_or_exit("MacOSX/QuickTime/Version");
fixed_version = "7.6.9";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since QuickTime "+version+" is installed.");
