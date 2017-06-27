#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74432);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2014-0531",
    "CVE-2014-0532",
    "CVE-2014-0533",
    "CVE-2014-0534",
    "CVE-2014-0535",
    "CVE-2014-0536"
  );
  script_bugtraq_id(67961, 67962, 67963, 67970, 67973, 67974);
  script_osvdb_id(107822, 107823, 107824, 107825, 107826, 107827);

  script_name(english:"Adobe AIR for Mac <= 13.0.0.111 Multiple Vulnerabilities (APSB14-16)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a version of Adobe AIR that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR on the remote Mac
OS X host is equal or prior to 13.0.0.111. It is, therefore, affected
by the following vulnerabilities :

  - Multiple, unspecified errors exist that could allow
    cross-site scripting attacks. (CVE-2014-0531,
    CVE-2014-0532, CVE-2014-0533)

  - Multiple, unspecified errors exist that could allow
    unspecified security bypass attacks. (CVE-2014-0534,
    CVE-2014-0535)

  - An unspecified memory corruption issue exists that
    could allow arbitrary code execution. (CVE-2014-0536)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-16.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 14.0.0.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
cutoff_version = '13.0.0.111';
fixed_version_for_report = '14.0.0.110';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
