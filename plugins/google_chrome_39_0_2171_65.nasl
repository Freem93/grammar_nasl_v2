#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79336);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2014-0574",
    "CVE-2014-7899",
    "CVE-2014-7900",
    "CVE-2014-7901",
    "CVE-2014-7902",
    "CVE-2014-7903",
    "CVE-2014-7904",
    "CVE-2014-7906",
    "CVE-2014-7907",
    "CVE-2014-7908",
    "CVE-2014-7909",
    "CVE-2014-7910"
  );
  script_bugtraq_id(
    71041,
    71158,
    71159,
    71160,
    71161,
    71163,
    71164,
    71165,
    71166,
    71167,
    71168,
    71170
  );
  script_osvdb_id(
    114494,
    114757,
    114758,
    114759,
    114760,
    114761,
    114762,
    114764,
    114765,
    114766,
    114767
  );

  script_name(english:"Google Chrome < 39.0.2171.65 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is a
version prior to 39.0.2171.65. It is, therefore, affected by the
following vulnerabilities :

  - A double-free vulnerability exists in the version of
    Adobe Flash bundled with Chrome which could result in
    arbitrary code execution. (CVE-2014-0574)

  - An unspecified address bar spoofing vulnerability
    exists which could be used to aid in phishing attacks.
    (CVE-2014-7899)

  - Multiple use-after-free vulnerabilities exist in pdfium
    which could result in arbitrary code execution.
    (CVE-2014-7900, CVE-2014-7902)

  - Integer overflow vulnerabilities exist in pdfium and
    the media component which could result in arbitrary
    code execution. (CVE-2014-7901, CVE-2014-7908)

  - Buffer overflow vulnerabilities exist in pdfium and
    Skia which could result in arbitrary code execution.
    (CVE-2014-7903, CVE-2014-7904)

  - Use-after-free vulnerabilities exist in Pepper plugins
    and Blink which could result in arbitrary code
    execution. (CVE-2014-7906, CVE-2014-7907)

  - An unspecified uninitialized memory read exists.
    (CVE-2014-7909)

  - Multiple unspecified vulnerabilities exist.
    (CVE-2014-7910)");
  # http://googlechromereleases.blogspot.com/2014/11/stable-channel-update_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc00508c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 39.0.2171.65 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'39.0.2171.65', severity:SECURITY_HOLE, xss:FALSE);
