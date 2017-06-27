#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93477);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2016-5170",
    "CVE-2016-5171",
    "CVE-2016-5172",
    "CVE-2016-5173",
    "CVE-2016-5174",
    "CVE-2016-5175",
    "CVE-2016-5176"
  );
  script_bugtraq_id(92942);
  script_osvdb_id(
    144196,
    144197,
    144198,
    144199,
    144200,
    144201,
    144214,
    144981
  );

  script_name(english:"Google Chrome < 53.0.2785.113 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 53.0.2785.113. It is, therefore, affected by multiple
vulnerabilities :

  - A use-after-free error exists in the file
    bindings/modules/v8/V8BindingForModules.cpp that allows
    an unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-5170)

  - A use-after-free error exists in Blink that is related
    to window constructors being callable. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5171)

  - An arbitrary memory read error exists in V8 that allows
    an unauthenticated, remote attacker to disclose
    sensitive memory information. (CVE-2016-5172)

  - A flaw exists due to improper handling of specially
    crafted web pages. An unauthenticated, remote attacker
    can exploit this to load JavaScript extension resources,
    which may then be used to perform unauthorized actions.
    (CVE-2016-5173)

  - A flaw exists that is triggered when in fullscreen mode,
    in file ui/cocoa/browser_window_controller_private.mm,
    that results in a failure to suppress popups.
    (CVE-2016-5174)

  - An unspecified flaw exists that allows an attacker to
    impact confidentiality, integrity, and availability.
    (CVE-2016-5175, VulnDB 144201)

  - A flaw exists due to improper handling of IPC messages
    for dead routing IDs. An authenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-5175, VulnDB 144214)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to bypass the
    SafeBrowsing protection mechanism. (CVE-2016-5176)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://googlechromereleases.blogspot.com/2016/09/stable-channel-update-for-desktop_13.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?d15fba3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 53.0.2785.113 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'53.0.2785.113', severity:SECURITY_HOLE);
