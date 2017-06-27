#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88640);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id(
    "CVE-2016-0964", 
    "CVE-2016-0965", 
    "CVE-2016-0966", 
    "CVE-2016-0967", 
    "CVE-2016-0968", 
    "CVE-2016-0969", 
    "CVE-2016-0970", 
    "CVE-2016-0971", 
    "CVE-2016-0972", 
    "CVE-2016-0973", 
    "CVE-2016-0974", 
    "CVE-2016-0975", 
    "CVE-2016-0976", 
    "CVE-2016-0977", 
    "CVE-2016-0978", 
    "CVE-2016-0979", 
    "CVE-2016-0980", 
    "CVE-2016-0981", 
    "CVE-2016-0982", 
    "CVE-2016-0983", 
    "CVE-2016-0984", 
    "CVE-2016-0985"
  );
  script_osvdb_id(
    134259,
    134260,
    134261,
    134262,
    134263,
    134264,
    134265,
    134266,
    134267,
    134268,
    134269,
    134270,
    134271,
    134272,
    134273,
    134274,
    134275,
    134276,
    134277,
    134278,
    134279,
    134280
  );

  script_name(english:"Adobe AIR for Mac <= 20.0.0.233 Multiple Vulnerabilities (APSB16-04)");
  script_summary(english:"Checks the version of AIR.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Mac OS X host is
prior or equal to version 20.0.0.233. It is, therefore, affected by
multiple vulnerabilities :

  - A type confusion error exists that allows a remote
    attacker to execute arbitrary code. (CVE-2016-0985)

  - Multiple use-after-free errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-0973,
    CVE-2016-0974, CVE-2016-0975, CVE-2016-0982,
    CVE-2016-0983, CVE-2016-0984)

  - A heap buffer overflow condition exist that allows an 
    attacker to execute arbitrary code. (CVE-2016-0971)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-0964, CVE-2016-0965, CVE-2016-0966,
    CVE-2016-0967, CVE-2016-0968, CVE-2016-0969,
    CVE-2016-0970, CVE-2016-0972, CVE-2016-0976,
    CVE-2016-0977, CVE-2016-0978, CVE-2016-0979,
    CVE-2016-0980, CVE-2016-0981)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-04.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 20.0.0.260 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
cutoff_version = '20.0.0.233';
fixed_version_for_report = '20.0.0.260';

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
