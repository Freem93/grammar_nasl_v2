#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(55763);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2011-0186",
    "CVE-2011-0187",
    "CVE-2011-0209",
    "CVE-2011-0210",
    "CVE-2011-0211",
    "CVE-2011-0213",
    "CVE-2011-0245",
    "CVE-2011-0249",
    "CVE-2011-0250",
    "CVE-2011-0251",
    "CVE-2011-0252",
    "CVE-2011-0256",
    "CVE-2011-0257"
  );
  script_bugtraq_id(
    46992,
    46995,
    48419,
    48420,
    48430,
    48442,
    49028,
    49034,
    49035,
    49036,
    49038,
    49144,
    49170
  );
  script_osvdb_id(
    71638,
    71639,
    73358,
    73359,
    73373,
    73375,
    74266,
    74270,
    74271,
    74272,
    74273,
    74686,
    74687
  );

  script_name(english:"QuickTime < 7.7 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains an application that may be affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.7.  As such, it reportedly may be affected by the
following vulnerabilities :

  - A buffer overflow in QuickTime's handling of pict files
    may lead to an application crash or arbitrary code
    execution. (CVE-2011-0245)

  - A buffer overflow in QuickTime's handling of JPEG2000
    files may lead to an application crash or arbitrary
    code execution. (CVE-2011-0186)

  - A cross-origin issue in QuickTime plug-in's handling of
    cross-site redirects may lead to disclosure of video
    data from another site. (CVE-2011-0187)

  - An integer overflow in QuickTime's handling of RIFF WAV
    files may lead to an application crash or arbitrary
    code execution. (CVE-2011-0209)

  - A memory corruption issue in QuickTime's handling of
    sample tables in QuickTime movie files may lead to an
    application crash or arbitrary code execution.
    (CVE-2011-0210)

  - An integer overflow in QuickTime's handling of audio
    channels in movie files may lead to an application
    crash or arbitrary code execution. (CVE-2011-0211)

  - A buffer overflow in QuickTime's handling of JPEG files
    may lead to an application crash or arbitrary code
    execution. (CVE-2011-0213)

  - A heap-based buffer overflow in QuickTime's handling of
    STSC atoms in QuickTime movie files may lead to an
    application crash or arbitrary code execution.
    (CVE-2011-0249)

  - A heap-based buffer overflow in QuickTime's handling of
    STSS atoms in QuickTime movie files may lead to an
    application crash or arbitrary code execution.
    (CVE-2011-0250)

  - A heap-based buffer overflow in QuickTime's handling of
    STSZ atoms in QuickTime movie files may lead to an
    application crash or arbitrary code execution.
    (CVE-2011-0251)

  - A heap-based buffer overflow in QuickTime's handling of
    STTS atoms in QuickTime movie files may lead to an
    application crash or arbitrary code execution.
    (CVE-2011-0252)

  - A stack-based buffer overflow in QuickTime's handling of
    PICT files may lead to an application crash or arbitrary
    code execution. (CVE-2011-0257)

  - An integer overflow in QuickTime's handling of track run
    atoms in QuickTime movie files may lead to an
    application crash or arbitrary code execution.
    (CVE-2011-0256)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-254/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-257/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-258/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-259/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Aug/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to QuickTime 7.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime PICT PnSize Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Quicktime652.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/QuickTime/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");


# Mac OS X 10.5 only.
os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (!ereg(pattern:"Mac OS X 10\.5([^0-9]|$)", string:os)) 
  exit(0, "The host is running "+os+" and therefore is not affected.");


version = get_kb_item_or_exit("MacOSX/QuickTime/Version");
fixed_version = "7.7";

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
