#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86370);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:42:41 $");

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

  script_name(english:"Adobe Flash Player for Mac <= 19.0.0.185 Multiple Vulnerabilities (APSB15-25)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 19.0.0.185. It is, therefore,
affected by multiple vulnerabilities :

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
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 19.0.0.207 or later.

Alternatively, Adobe has made version 18.0.0.252 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

fix = FALSE;
if(version =~ "^19\." && ver_compare(ver:version, fix:"19.0.0.185", strict:FALSE) <= 0)
  fix = "19.0.0.207";
else if(ver_compare(ver:version, fix:"18.0.0.241") <= 0)
  fix = "18.0.0.252";

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
