#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73766);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2014-1492",
    "CVE-2014-1518",
    "CVE-2014-1519",
    "CVE-2014-1522",
    "CVE-2014-1523",
    "CVE-2014-1524",
    "CVE-2014-1525",
    "CVE-2014-1526",
    "CVE-2014-1529",
    "CVE-2014-1530",
    "CVE-2014-1531",
    "CVE-2014-1532"
  );
  script_bugtraq_id(
    66356,
    67123,
    67125,
    67127,
    67129,
    67130,
    67131,
    67132,
    67134,
    67135,
    67136,
    67137
  );
  script_osvdb_id(
    104708,
    106396,
    106397,
    106398,
    106401,
    106402,
    106403,
    106404,
    106405,
    106406
  );

  script_name(english:"Firefox < 29.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is a version prior to version 29.0.
It is, therefore, potentially affected by multiple vulnerabilities :

  - An issue exists in the Network Security (NSS) library
    due to improper handling of IDNA domain prefixes for
    wildcard certificates. This issue could allow man-in-
    the-middle attacks. (CVE-2014-1492)

  - Memory issues exist that could lead to arbitrary code
    execution. (CVE-2014-1518, CVE-2014-1519)

  - An out-of-bounds read issue exists in the Web Audio
    feature that could lead to information disclosure.
    (CVE-2014-1522)

  - An out-of-bounds read issue exists when decoding
    certain JPG images that could lead to a denial of
    service. (CVE-2014-1523)

  - A memory corruption issue exists due to improper
    validation of XBL objects that could lead to arbitrary
    code execution. (CVE-2014-1524)

  - A use-after-free memory issue exists in the Text Track
    Manager during HTML video processing that could lead
    to arbitrary code execution. (CVE-2014-1525)

  - An issue exists related to the debugger bypassing
    XrayWrappers that could lead to privilege escalation.
    (CVE-2014-1526)

  - A security bypass issue exists in the Web Notification
    API that could lead to arbitrary code execution.
    (CVE-2014-1529)

  - A cross-site scripting issue exists that could allow an
    attacker to load another website other than the URL for
    the website that is shown in the address bar.
    (CVE-2014-1530)

  - A use-after-free issue exists due to an 'imgLoader'
    object being freed when being resized.  This issue
    could lead to arbitrary code execution. (CVE-2014-1531)

  - A use-after-free issue exists during host resolution
    that could lead to arbitrary code execution.
    (CVE-2014-1532)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-35.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-36.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-37.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-38.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-39.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-42.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-43.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-44.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-45.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-46.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-47.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 29.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'29.0', severity:SECURITY_HOLE, xss:TRUE);
