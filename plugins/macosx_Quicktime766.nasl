#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(45387);
  script_version("$Revision: 1.11 $");

  script_cve_id(
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
    "CVE-2010-0526"
  );
  script_bugtraq_id(
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
    63406
  );

  script_name(english:"QuickTime < 7.6.6 Multiple Vulnerabilities (Mac OS X)");
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
older than 7.6.6.  Such versions contain several vulnerabilities :

  - A memory corruption issue in QuickTime's handling of
    QDM2 encoded audio content may lead to an application 
    crash or arbitrary code execution. (CVE-2010-0059)

  - A memory corruption issue in QuickTime's handling of
    QDMC encoded audio content may lead to an application 
    crash or arbitrary code execution. (CVE-2010-0060)

  - A heap buffer overflow in QuickTime's handling of H.263
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0062)

  - A heap buffer overflow in QuickTime's handling of H.261
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0514)

  - A memory corruption issue in QuickTime's handling of
    H.264 encoded movie files may lead to an application 
    crash or arbitrary code execution. (CVE-2010-0515)

  - A heap buffer overflow in QuickTime's handling of RLE
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0516)

  - A heap buffer overflow in QuickTime's handling of M-JPEG
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0517)

  - A memory corruption issue in QuickTime's handling of
    Sorenson encoded movie files may lead to an application
    crash or arbitrary code execution. (CVE-2010-0518)

  - An integer overflow in QuickTime's handling of FlashPix
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0519)

  - A heap buffer overflow in QuickTime's handling of FLC
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0520)

  - A heap buffer overflow in QuickTime's handling of MPEG
    encoded movie files may lead to an application crash or
    arbitrary code execution. (CVE-2010-0526)"
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
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/31");
 script_cvs_date("$Date: 2012/02/06 18:28:58 $");
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


uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(1, "Can't identify the Darwin kernel version from the uname output ("+uname+").");

darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^[0-8]\.", string:darwin)) exit(0, "The host is running Darwin kernel version "+darwin+", which is no longer supported by Apple.");

version = get_kb_item("MacOSX/QuickTime/Version");
if (isnull(version)) exit(1, "The 'MacOSX/QuickTime/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 || 
  (
    ver[0] == 7 && 
    (
      ver[1] < 6 ||
      (ver[1] == 6 && ver[2] < 6)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'QuickTime ' + version + ' is currently installed on the remote host.\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since QuickTime "+version+" is installed.");
