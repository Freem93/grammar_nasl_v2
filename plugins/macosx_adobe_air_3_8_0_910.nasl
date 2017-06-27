#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70215);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id("CVE-2013-3344", "CVE-2013-3345", "CVE-2013-3347");
  script_bugtraq_id(61043, 61045, 61048);
  script_osvdb_id(94988, 94989, 94990);

  script_name(english:"Adobe AIR for Mac <= 3.7.0.2100 Multiple Vulnerabilities (APSB13-17)");
  script_summary(english:"Checks version gathered by local check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Adobe AIR on the remote Mac
OS X host is 3.7.0.2100 or earlier.  It is, therefore, potentially
affected by multiple vulnerabilities :

  - A heap-based buffer overflow vulnerability exists that
    could lead to code execution. (CVE-2013-3344)

  - A memory corruption vulnerability exists that could lead
    to code execution. (CVE-2013-3345)

  - An integer overflow exists when resampling a user-
    supplied PCM buffer. (CVE-2013-3347)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-17.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 3.8.0.910 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '3.7.0.2100';
fixed_version_for_report = '3.8.0.910';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
