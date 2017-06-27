#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92013);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/06 18:19:46 $");

  script_cve_id(
    "CVE-2016-4172",
    "CVE-2016-4173",
    "CVE-2016-4174",
    "CVE-2016-4175",
    "CVE-2016-4176",
    "CVE-2016-4177",
    "CVE-2016-4178",
    "CVE-2016-4179",
    "CVE-2016-4180",
    "CVE-2016-4181",
    "CVE-2016-4182",
    "CVE-2016-4183",
    "CVE-2016-4184",
    "CVE-2016-4185",
    "CVE-2016-4186",
    "CVE-2016-4187",
    "CVE-2016-4188",
    "CVE-2016-4189",
    "CVE-2016-4190",
    "CVE-2016-4217",
    "CVE-2016-4218",
    "CVE-2016-4219",
    "CVE-2016-4220",
    "CVE-2016-4221",
    "CVE-2016-4222",
    "CVE-2016-4223",
    "CVE-2016-4224",
    "CVE-2016-4225",
    "CVE-2016-4226",
    "CVE-2016-4227",
    "CVE-2016-4228",
    "CVE-2016-4229",
    "CVE-2016-4230",
    "CVE-2016-4231",
    "CVE-2016-4232",
    "CVE-2016-4233",
    "CVE-2016-4234",
    "CVE-2016-4235",
    "CVE-2016-4236",
    "CVE-2016-4237",
    "CVE-2016-4238",
    "CVE-2016-4239",
    "CVE-2016-4240",
    "CVE-2016-4241",
    "CVE-2016-4242",
    "CVE-2016-4243",
    "CVE-2016-4244",
    "CVE-2016-4245",
    "CVE-2016-4246",
    "CVE-2016-4247",
    "CVE-2016-4248",
    "CVE-2016-4249",
    "CVE-2016-7020"
  );
  script_bugtraq_id(
    91718,
    91719,
    91720,
    91721,
    91722,
    91723,
    91724,
    91725
  );
  script_osvdb_id(
    141309,
    141310,
    141311,
    141312,
    141313,
    141314,
    141315,
    141316,
    141317,
    141318,
    141319,
    141320,
    141321,
    141322,
    141323,
    141324,
    141325,
    141326,
    141327,
    141328,
    141329,
    141330,
    141331,
    141332,
    141333,
    141334,
    141335,
    141336,
    141337,
    141338,
    141339,
    141340,
    141341,
    141342,
    141343,
    141344,
    141345,
    141346,
    141347,
    141348,
    141349,
    141350,
    141351,
    141352,
    141353,
    141354,
    141355,
    141356,
    141359,
    141360,
    141380,
    141381,
    145170
  );
  
  script_name(english:"Adobe Flash Player for Mac <= 22.0.0.192 Multiple Vulnerabilities (APSB16-25)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 22.0.0.192. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-4172, CVE-2016-4175, CVE-2016-4179,
    CVE-2016-4180, CVE-2016-4181, CVE-2016-4182,
    CVE-2016-4183, CVE-2016-4184, CVE-2016-4185,
    CVE-2016-4186, CVE-2016-4187, CVE-2016-4188,
    CVE-2016-4189, CVE-2016-4190, CVE-2016-4217,
    CVE-2016-4218, CVE-2016-4219, CVE-2016-4220,
    CVE-2016-4221, CVE-2016-4233, CVE-2016-4234,
    CVE-2016-4235, CVE-2016-4236, CVE-2016-4237,
    CVE-2016-4238, CVE-2016-4239, CVE-2016-4240,
    CVE-2016-4241, CVE-2016-4242, CVE-2016-4243,
    CVE-2016-4244, CVE-2016-4245, CVE-2016-4246)

  - Multiple use-after-free errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-4173,
    CVE-2016-4174, CVE-2016-4222, CVE-2016-4226,
    CVE-2016-4227, CVE-2016-4228, CVE-2016-4229,
    CVE-2016-4230, CVE-2016-4231, CVE-2016-4248,
    CVE-2016-7020)

  - Multiple stack corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-4176, CVE-2016-4177)

  - A security bypass vulnerability exists that allows a
    remote attacker to disclose sensitive information.
    (CVE-2016-4178)

  - Multiple type confusion errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-4223,
    CVE-2016-4224, CVE-2016-4225)

  - An unspecified memory leak issue exists that allows an
    attacker to have an unspecified impact. (CVE-2016-4232)

  - A race condition exists that allows a remote attacker to
    disclose sensitive information. (CVE-2016-4247)

  - A heap buffer overflow condition exists that allows a
    remote attacker to execute arbitrary code.
    (CVE-2016-4249)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-25.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 22.0.0.209 or later.

Alternatively, Adobe has made version 18.0.0.366 available for those installs
that cannot be upgraded to the latest version");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"19.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "22.0.0.192";
  fix = "22.0.0.209";
}
else
{
  cutoff_version = "18.0.0.360";
  fix = "18.0.0.366";
}

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
