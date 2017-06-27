#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86063);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id(
    "CVE-2015-5567",
    "CVE-2015-5568",
    "CVE-2015-5570",
    "CVE-2015-5571",
    "CVE-2015-5572",
    "CVE-2015-5573",
    "CVE-2015-5574",
    "CVE-2015-5575",
    "CVE-2015-5576",
    "CVE-2015-5577",
    "CVE-2015-5578",
    "CVE-2015-5579",
    "CVE-2015-5580",
    "CVE-2015-5581",
    "CVE-2015-5582",
    "CVE-2015-5584",
    "CVE-2015-5587",
    "CVE-2015-5588",
    "CVE-2015-6676",
    "CVE-2015-6677",
    "CVE-2015-6678",
    "CVE-2015-6679",
    "CVE-2015-6682"
  );
  script_osvdb_id(
    127803,
    127804,
    127805,
    127806,
    127807,
    127808,
    127809,
    127810,
    127811,
    127812,
    127813,
    127814,
    127815,
    127816,
    127817,
    127818,
    127819,
    127820,
    127821,
    127822,
    127823,
    127824,
    127825
  );

  script_name(english:"Adobe Flash Player for Mac <= 18.0.0.232 Multiple Vulnerabilities (APSB15-23)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 18.0.0.232. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified stack corruption issue exists that
    allows a remote attacker to execute arbitrary code.
    (CVE-2015-5567, CVE-2015-5579)

  - A vector length corruption issue exists that allows a
    remote attacker to have an unspecified impact.
    (CVE-2015-5568)

  - A use-after-free error exists in an unspecified
    component due to improperly sanitized user-supplied
    input. A remote attacker can exploit this, via a
    specially crafted file, to deference already freed
    memory and execute arbitrary code. (CVE-2015-5570,
    CVE-2015-5574, CVE-2015-5581, CVE-2015-5584,
    CVE-2015-6682)

  - An unspecified flaw exists due to a failure to reject
    content from vulnerable JSONP callback APIs. A remote
    attacker can exploit this to have an unspecified impact.
    (CVE-2015-5571)

  - An unspecified flaw exists that allows a remote attacker
    to bypass security restrictions and gain access to
    sensitive information. (CVE-2015-5572)

  - An unspecified type confusion flaw exists that allows a
    remote attacker to execute arbitrary code.
    (CVE-2015-5573)

  - A flaw exists in an unspecified component due to
    improper validation of user-supplied input when handling
    a specially crafted file. A remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    or the execution of arbitrary code. (CVE-2015-5575,
    CVE-2015-5577, CVE-2015-5578, CVE-2015-5580,
    CVE-2015-5582, CVE-2015-5588, CVE-2015-6677)

  - A memory leak issue exists that allows a remote
    attacker to have an unspecified impact. (CVE-2015-5576)

  - A stack buffer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-5587)

  - An unspecified overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-6676,
    CVE-2015-6678)

  - An unspecified flaw exists that allows a remote attacker
    to bypass same-origin policy restrictions and gain
    access to sensitive information. (CVE-2015-6679)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-23.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 19.0.0.185 or later.

Alternatively, Adobe has made version 18.0.0.241 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

cutoff_version = "18.0.0.232";
fix = "19.0.0.185 / 18.0.0.241";

# we're checking for versions less than or equal to the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
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
