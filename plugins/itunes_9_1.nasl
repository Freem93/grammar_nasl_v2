#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45390);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/08/03 13:57:41 $");

  script_cve_id(
    "CVE-2009-2285",
    "CVE-2010-0040",
    "CVE-2010-0041",
    "CVE-2010-0042",
    "CVE-2010-0043",
    "CVE-2010-0531",
    "CVE-2010-0532",
    "CVE-2010-1795"
  );
  script_bugtraq_id(38673, 38674, 38676, 38677, 39092, 42541);
  script_osvdb_id(
    55265,
    62933,
    62934,
    62935,
    62936,
    62949,
    62950,
    63449,
    63450,
    67329
  );

  script_name(english:"Apple iTunes < 9.1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Windows host is
older than 9.1. Such versions may be affected by multiple
vulnerabilities :

  - A buffer underflow in ImageIO's handling of TIFF images
    may lead to an application crash or arbitrary code 
    execution. (CVE-2009-2285)

  - An integer overflow in the applications's handling of
    images with an embedded color profile may lead to an 
    application crash or arbitrary code execution.
    (CVE-2010-0040)

  - An uninitialized memory access issue in ImageIO's
    handling of BMP images may result in sending data from
    Safari's memory to a website under an attacker's 
    control. (CVE-2010-0041)

  - An uninitialized memory access issue in ImageIO's
    handling of TIFF images may result in sending data from
    Safari's memory to a website under an attacker's 
    control. (CVE-2010-0042)

  - A memory corruption issue in the application's handling
    of TIFF images may lead to an application crash or 
    arbitrary code execution. (CVE-2010-0043)

  - A race condition during the installation process may
    allow a local user modify a file that is then executed
    with SYSTEM privileges. (CVE-2010-0532)

  - A path searching issue may allow code execution if an
    attacker can place a specially crafted DLL in a 
    directory and have a user open another file using 
    iTunes in that directory. (CVE-2010-1795)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4105"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/19388"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apple iTunes 9.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include ("global_settings.inc");


version = get_kb_item("SMB/iTunes/Version");
if (isnull(version)) exit(1, "The 'SMB/iTunes/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 ||
  (
    ver[0] == 9 && 
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] == 0 && ver[3] < 79)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'iTunes ' + version + ' is installed on the remote host.\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since iTunes "+version+" is installed.");
