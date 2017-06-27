#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100053);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/17 14:28:39 $");

  script_cve_id(
    "CVE-2017-3068",
    "CVE-2017-3069",
    "CVE-2017-3070",
    "CVE-2017-3071",
    "CVE-2017-3072",
    "CVE-2017-3073",
    "CVE-2017-3074"
  );
  script_bugtraq_id(
    98347,
    98349,
    98349,
    98349,
    98349,
    98349,
    98349
  );
  script_osvdb_id(
    157209,
    157210,
    157211,
    157212,
    157213,
    157214,
    157215
  );
  script_xref(name:"IAVA", value:"2017-A-0134");

  script_name(english:"Adobe Flash Player for Mac <= 25.0.0.163 Multiple Vulnerabilities (APSB17-15)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host has a browser plugin installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote macOS or Mac
OS X host is equal or prior to version 25.0.0.163. It is, therefore,
affected by multiple vulnerabilities :

  - A use-after-free error exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-3071)

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-3068, CVE-2017-3069, CVE-2017-3070,
    CVE-2017-3072, CVE-2017-3073, CVE-2017-3074)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-15.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 25.0.0.171 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

cutoff_version = "25.0.0.163";
fix = "25.0.0.171";
# we're checking for versions less than or equal to the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
   info =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:info, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
