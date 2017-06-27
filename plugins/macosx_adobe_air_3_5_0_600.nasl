#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62837);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");
  
  script_cve_id(
    "CVE-2012-5274",
    "CVE-2012-5275",
    "CVE-2012-5276",
    "CVE-2012-5277",
    "CVE-2012-5278",
    "CVE-2012-5279",
    "CVE-2012-5280"
  );
  script_bugtraq_id(56542, 56543, 56544, 56545, 56546, 56547, 56554);
  script_osvdb_id(87064, 87065, 87066, 87067, 87068, 87069, 87070);

  script_name(english:"Adobe AIR for Mac 3.x <= 3.4.0.2710 Multiple Vulnerabilities (APSB12-24)");
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
OS X host is 3.4.0.2710 or earlier.  It is, therefore, reportedly
affected by multiple vulnerabilities :

  - Several unspecified issues exist that can lead to buffer
    overflows and arbitrary code execution. (CVE-2012-5274,
    CVE-2012-5275, CVE-2012-5276, CVE-2012-5277,
    CVE-2012-5280)

  - An unspecified security bypass issue exists that can
    lead to arbitrary code execution. (CVE-2012-5278)

  - An unspecified issue exists that can lead to memory
    corruption and arbitrary code execution. (CVE-2012-5279)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-24.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 3.5.0.600 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/07");


  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
cutoff_version = '3.4.0.2710';
fixed_version_for_report = '3.5.0.600';

if (version =~ '^3\\.' && ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
