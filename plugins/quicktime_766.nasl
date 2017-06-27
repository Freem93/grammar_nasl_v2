#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(45388);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/12 22:56:25 $");

  script_cve_id(
    "CVE-2009-2837",
    "CVE-2010-0059",
    "CVE-2010-0060",
    "CVE-2010-0062",
    "CVE-2010-0514",
    "CVE-2010-0515",
    "CVE-2010-0516",
    "CVE-2010-0517",
    "CVE-2010-0518",
    "CVE-2010-0519",
    "CVE-2010-0520",
    "CVE-2010-0526",
    "CVE-2010-0527",
    "CVE-2010-0528",
    "CVE-2010-0529",
    "CVE-2010-0536"
  );
  script_bugtraq_id(
    39136,
    39139,
    39140,
    39141,
    39152,
    39154,
    39155,
    39159,
    39161,
    39163,
    39164,
    39165,
    39166,
    39167
  );
  script_osvdb_id(
    59994,
    63365,
    63376,
    63381,
    63388,
    63390,
    63394,
    63396,
    63400,
    63401,
    63403,
    63406,
    63447,
    63448,
    63451
  );

  script_name(english:"QuickTime < 7.6.6 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of QuickTime installed on the remote Windows host is older
than 7.6.6.  Such versions contain several vulnerabilities :

  - A heap-based buffer overflow in QuickTime's handling of
    PICT images may lead to an application crash or
    arbitrary code execution. (CVE-2009-2837)

  - A memory corruption issue in QuickTime's handling of
    QDM2 encoded audio content may lead to an application
    crash or arbitrary code execution. (CVE-2010-0059)

  - A memory corruption issue in QuickTime's handling of
    QDMC encoded audio content may lead to an application
    crash or arbitrary code execution. (CVE-2010-0060)

  - A heap-based buffer overflow in QuickTime's handling of
    H.263 encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0062)

  - A heap-based buffer overflow in QuickTime's handling of
    H.261 encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0514)

  - A memory corruption issue in QuickTime's handling of
    H.264 encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0515)

  - A heap-based buffer overflow in QuickTime's handling of
    RLE encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0516)

  - A heap-based buffer overflow in QuickTime's handling of
    M-JPEG encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0517)

  - A memory corruption issue in QuickTime's handling of
    Sorenson encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0518)

  - An integer overflow in QuickTime's handling of FlashPix
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0519)

  - A heap-based buffer overflow in QuickTime's handling of
    FLC encoded movie files may lead to an application crash
    or arbitrary code execution. (CVE-2010-0520)

  - A heap-based buffer overflow in QuickTime's handling of
    MPEG encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0526)

  - An integer overflow in QuickTime's handling of PICT
    images may lead to an application crash or arbitrary
    code execution. (CVE-2010-0527)

  - A memory corruption issue in QuickTime's handling of
    color tables in movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0528)

  - A heap-based buffer overflow in QuickTime's handling of
    PICT images may lead to an application crash or
    arbitrary code execution. (CVE-2010-0529)

  - A memory corruption issue in QuickTime's handling of
    BMP images may lead to an application crash or arbitrary
    code execution. (CVE-2010-0536)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/19386"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to QuickTime 7.6.6 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/QuickTime/Version_UI");
version = get_kb_item("SMB/QuickTime/Version");
if (isnull(version)) exit(1, "The 'SMB/QuickTime/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 || 
  (
    ver[0] == 7 && 
    (
      ver[1] < 66 ||
      (ver[1] == 66 && ver[2] < 71)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'QuickTime ' + version_report + ' is currently installed on the remote host.\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since QuickTime "+version_report+" is installed.");
