#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56962);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 16:53:07 $");

  script_cve_id(
    "CVE-2011-2445",
    "CVE-2011-2450",
    "CVE-2011-2451",
    "CVE-2011-2452",
    "CVE-2011-2453",
    "CVE-2011-2454",
    "CVE-2011-2455",
    "CVE-2011-2456",
    "CVE-2011-2457",
    "CVE-2011-2459",
    "CVE-2011-2460"
  );
  script_bugtraq_id(
    50618,
    50619,
    50620,
    50621,
    50622,
    50623,
    50624,
    50625,
    50626,
    50627,
    50628
  );
  script_osvdb_id(
    77018,
    77019,
    77020,
    77021,
    77022,
    77023,
    77024,
    77025,
    77026,
    77028,
    77029
  );

  script_name(english:"Adobe AIR for Mac <= 3.0 Multiple Vulnerabilities (APSB11-28)");
  script_summary(english:"Checks version of Adobe AIR from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Adobe AIR installed on the
remote Mac OS X host is 3.0 or earlier.  It is therefore reportedly
affected by several critical vulnerabilities :

  - Several unspecified memory corruption errors
    exist that could lead to code execution.
    (CVE-2011-2445, CVE-2011-2451, CVE-2011-2452,
    CVE-2011-2453, CVE-2011-2454, CVE-2011-2455,
    CVE-2011-2459, CVE-2011-2460)

  - An unspecified heap corruption error exists that could
    lead to code execution. (CVE-2011-2450)

  - An unspecified buffer overflow error exists that could
    lead to code execution. (CVE-2011-2456)

  - An unspecified stack overflow error exists that could
    lead to code execution. (CVE-2011-2457)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR version 3.1.0.4880 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");


# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '3.0';
fixed_version_for_report = '3.1.0.4880';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item_or_exit(kb_base+"/Path");
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The Adobe AIR for Mac "+version+" install on the host is not affected.");
