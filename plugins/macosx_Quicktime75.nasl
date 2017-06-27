#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33131);
  script_version("$Revision: 1.15 $");

  script_cve_id(
    "CVE-2008-1582",
    "CVE-2008-1583",
    "CVE-2008-1584",
    "CVE-2008-1585"
  );
  script_bugtraq_id(29619, 29648, 29650, 29652, 29654);
  script_osvdb_id(46070, 46071, 46072, 46073);
  script_xref(name:"Secunia", value:"29293");

  script_name(english:"QuickTime < 7.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.5.  Such versions contain several vulnerabilities :

  - There is a heap-based buffer overflow in QuickTime's
    handling of PICT image files that could result in a
    program crash or arbitrary code execution
    (CVE-2008-1583).

  - There is a memory corruption issue in QuickTime's
    handling of AAC-encoded media content that could
    result in a program crash or arbitrary code execution
    (CVE-2008-1582).

  - There is a stack-based buffer overflow in QuickTime's
    handling of Indeo video codec content that could
    result in a program crash or arbitrary code execution
    (CVE-2008-1584).

  - There is a URL handling issue in QuickTime's handling
    of 'file:' URLs that may allow launching of arbitrary
    applications (CVE-2008-1585)." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1991" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-037" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-038" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493247/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493248/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Jun/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 119, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/10");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/06/09");
script_cvs_date("$Date: 2016/11/28 21:06:38 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

include("global_settings.inc");

ver = get_kb_item("MacOSX/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 || 
  (iver[0] == 7 && iver[1] < 5)
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "QuickTime ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
