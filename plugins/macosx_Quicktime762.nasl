#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38989);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    "CVE-2009-0185", 
    "CVE-2009-0188", 
    "CVE-2009-0951", 
    "CVE-2009-0952", 
    "CVE-2009-0953",
    "CVE-2009-0955", 
    "CVE-2009-0956", 
    "CVE-2009-0957"
  );
  script_bugtraq_id(
    35159, 
    35161, 
    35162, 
    35163, 
    35164, 
    35165, 
    35166, 
    35167, 
    35168
  );
  script_osvdb_id(
    54873, 
    54874, 
    54876, 
    54877, 
    54878, 
    54879, 
    55033, 
    55071
  );

  script_name(english:"QuickTime < 7.6.2 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities."  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.6.2.  Such versions contain several vulnerabilities :

  - A heap buffer overflow in QuickTime's handling of MS 
    ADPCM encoded audio data may lead to an application 
    crash or arbitrary code execution. (CVE-2009-0185)

  - A memory corruption issue in QuickTime's handling of
    Sorenson 3 video files may lead to an application crash
    or arbitrary code execution. (CVE-2009-0188)

  - A heap buffer overflow in QuickTime's handling of FLC
    compression files may lead to an application crash or 
    arbitrary code execution. (CVE-2009-0951)

  - A buffer overflow in QuickTime's handling of compressed
    PSD image files may lead to an application crash or 
    arbitrary code execution. (CVE-2009-0952)

  - A heap buffer overflow in QuickTime's handling of PICT
    image files may lead to an application crash or 
    arbitrary code execution. (CVE-2009-0953)

  - A sign extension issue in QuickTime's handling of image
    description atoms in an Apple video file may lead to an
    application crash or arbitrary code execution. 
    (CVE-2009-0955)

  - An uninitialized memory access issue in QuickTime's 
    handling of movie files may lead to an application 
    crash or arbitrary code execution. (CVE-2009-0956)

  - A heap buffer overflow in QuickTime's handling of JP2
    image files may lead to an application crash or 
    arbitrary code execution. (CVE-2009-0957)"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3591"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Jun/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to QuickTime 7.6.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 119, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/06/01"); 
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

include("global_settings.inc");


version = get_kb_item("MacOSX/QuickTime/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 || 
  (
    ver[0] == 7 && 
    (
      ver[1] < 6 ||
      (ver[1] == 6 && ver[2] < 2)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "QuickTime ", version, " is currently installed on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
