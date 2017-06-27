#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86384);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id(
    "CVE-2015-5569",
    "CVE-2015-7625",
    "CVE-2015-7626",
    "CVE-2015-7627",
    "CVE-2015-7628",
    "CVE-2015-7629",
    "CVE-2015-7630",
    "CVE-2015-7631",
    "CVE-2015-7632",
    "CVE-2015-7633",
    "CVE-2015-7634",
    "CVE-2015-7643",
    "CVE-2015-7644"
  );
  script_osvdb_id(
    128762,
    128763,
    128764,
    128765,
    128766,
    128767,
    128768,
    128769,
    128770,
    128771,
    128772,
    128773,
    128774
  );

  script_name(english:"Adobe AIR for Mac <= 19.0.0.190 Multiple Vulnerabilities (APSB15-25)");
  script_summary(english:"Checks the version of AIR.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Mac OS X host is
equal or prior to version 19.0.0.190. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified vulnerability exists related to the
    defense-in-depth feature in the Flash Broker API. No
    other details are available. (CVE-2015-5569)

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-7625, CVE-2015-7626, CVE-2015-7627,
    CVE-2015-7630, CVE-2015-7633, CVE-2015-7634)

  - A unspecified vulnerability exists that can be exploited
    by a remote attacker to bypass the same-origin policy,
    allowing the disclosure of sensitive information.
    (CVE-2015-7628)

  - Multiple unspecified use-after-free errors exist that
    can be exploited by a remote attacker to deference
    already freed memory, potentially allowing the
    execution of arbitrary code. (CVE-2015-7629,
    CVE-2015-7631, CVE-2015-7643, CVE-2015-7644)

  - An unspecified buffer overflow condition exists due to
    improper validation of user-supplied input. An attacker
    can exploit this to execute arbitrary code.
    (CVE-2015-7632)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-25.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 19.0.0.213 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
cutoff_version = '19.0.0.190';
fixed_version_for_report = '19.0.0.213';

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
