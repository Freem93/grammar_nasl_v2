#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34118);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    "CVE-2008-3624",
    "CVE-2008-3625",
    "CVE-2008-3626",
    "CVE-2008-3627",
    "CVE-2008-3629"
  );
  script_bugtraq_id(31086, 31546, 31548);
  script_osvdb_id(48029, 48030, 48031, 48033, 48038, 48039, 48040);

  script_name(english:"QuickTime < 7.5.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.5.5.  Such versions contain several vulnerabilities :

  - Heap and stack-based buffer overflows in the handling of
    panorama atoms in QTVR (QuickTime Virtual Reality)
    movie files could lead to an application crash or
    arbitrary code execution (CVE-2008-3624 and
    CVE-2008-3625).

  - A memory corruption issue in QuickTime's handling of
    STSZ atoms in movie files could lead to an
    application crash or arbitrary code execution
    (CVE-2008-3626).

  - Multiple memory corruption issues in QuickTime's
    handling of H.264-encoded movie files could lead to
    an application crash or arbitrary code execution
    (CVE-2008-3627).

  - An out-of-bounds read issue in QuickTime's handling
    of PICT images could lead to an application crash
    (CVE-2008-3629)." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3027" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.5.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/10");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/09/09");
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
  (
    iver[0] == 7 && 
    (
      iver[1] < 5 ||
      (iver[1] == 5 && iver[2] < 5)
    )
  )
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
