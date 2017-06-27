#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86855);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2015-1302",
    "CVE-2015-7651",
    "CVE-2015-7652",
    "CVE-2015-7653",
    "CVE-2015-7654",
    "CVE-2015-7655",
    "CVE-2015-7656",
    "CVE-2015-7657",
    "CVE-2015-7658",
    "CVE-2015-7659",
    "CVE-2015-7660",
    "CVE-2015-7661",
    "CVE-2015-7662",
    "CVE-2015-7663",
    "CVE-2015-8042",
    "CVE-2015-8043",
    "CVE-2015-8044",
    "CVE-2015-8046"
  );
  script_osvdb_id(
    129999,
    130000,
    130001,
    130002,
    130003,
    130004,
    130005,
    130006,
    130007,
    130008,
    130009,
    130010,
    130011,
    130012,
    130013,
    130014,
    130015,
    130068
  );

  script_name(english:"Google Chrome < 46.0.2490.86 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 46.0.2490.86. It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists in the
    PDF viewer that allows an attacker to disclose sensitive
    information. (CVE-2015-1302)

  - A type confusion error exists that allows an attacker to
    execute arbitrary code. (CVE-2015-7659)

  - A security bypass vulnerability exists that allows an
    attacker to write arbitrary data to the file system
    under user permissions. (CVE-2015-7662)

  - Multiple use-after-free vulnerabilities exist that allow
    an attacker to execute arbitrary code. (CVE-2015-7651,
    CVE-2015-7652, CVE-2015-7653, CVE-2015-7654,
    CVE-2015-7655, CVE-2015-7656, CVE-2015-7657,
    CVE-2015-7658, CVE-2015-7660, CVE-2015-7661,
    CVE-2015-7663, CVE-2015-8042, CVE-2015-8043,
    CVE-2015-8044, CVE-2015-8046)");
  # http://googlechromereleases.blogspot.com/2015/11/stable-channel-update.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?f6a84f7c");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-28.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 46.0.2490.86 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'46.0.2490.86', severity:SECURITY_HOLE);
