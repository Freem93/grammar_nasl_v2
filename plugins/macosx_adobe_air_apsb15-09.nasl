#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84161);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2015-3044",
    "CVE-2015-3077",
    "CVE-2015-3078",
    "CVE-2015-3079",
    "CVE-2015-3080",
    "CVE-2015-3081",
    "CVE-2015-3082",
    "CVE-2015-3083",
    "CVE-2015-3084",
    "CVE-2015-3085",
    "CVE-2015-3086",
    "CVE-2015-3087",
    "CVE-2015-3088",
    "CVE-2015-3089",
    "CVE-2015-3090",
    "CVE-2015-3091",
    "CVE-2015-3092",
    "CVE-2015-3093"
  );
  script_bugtraq_id(
    74605,
    74608,
    74609,
    74610,
    74612,
    74613,
    74614,
    74616,
    74617
  );
  script_osvdb_id(
    120662,
    121927,
    121928,
    121929,
    121930,
    121931,
    121932,
    121933,
    121934,
    121935,
    121936,
    121937,
    121938,
    121939,
    121940,
    121941,
    121942,
    121943
  );

  script_name(english:"Adobe AIR for Mac <= 17.0.0.144 Multiple Vulnerabilities (APSB15-09)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a version of Adobe AIR installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe AIR on the remote
Mac OS X host is equal or prior to 17.0.0.144. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified security bypass vulnerability exists that
    allows an attacker to disclose sensitive information.
    (CVE-2015-3044)

  - Multiple unspecified type confusion flaws exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-3077, CVE-2015-3084, CVE-2015-3086)

  - Multiple memory corruption flaws exist due to improper
    validation of user-supplied input. A remote attacker can
    exploit these flaws, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-3078, CVE-2015-3089, CVE-2015-3090,
    CVE-2015-3093)

  - An unspecified security bypass exists that allows a
    context-dependent attacker to disclose sensitive
    information. (CVE-2015-3079)

  - An unspecified use-after-free error exists that allows
    an attacker to execute arbitrary code. (CVE-2015-3080)

  - An unspecified time-of-check time-of-use (TOCTOU) race
    condition exists that allows an attacker to bypass
    Protected Mode for Internet Explorer. (CVE-2015-3081)

  - Multiple validation bypass vulnerabilities exist that
    allow an attacker to read and write arbitrary data to
    the file system. (CVE-2015-3082, CVE-2015-3083,
    CVE-2015-3085)

  - An integer overflow condition exists due to improper
    validation of user-supplied input. This allows a
    context-dependent attacker to execute arbitrary code.
    (CVE-2015-3087)

  - A heap-based buffer overflow exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-3088)

  - Multiple unspecified memory leaks exist that allow an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-3091,
    CVE-2015-3092)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-09.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 17.0.0.172 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ShaderJob Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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
cutoff_version = '17.0.0.144';
fixed_version_for_report = '17.0.0.172';

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
