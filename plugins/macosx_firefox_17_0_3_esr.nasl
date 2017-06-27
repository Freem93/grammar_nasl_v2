#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64718);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 19:43:13 $");

  script_cve_id(
    "CVE-2013-0773",
    "CVE-2013-0774",
    "CVE-2013-0775",
    "CVE-2013-0776",
    "CVE-2013-0780",
    "CVE-2013-0782",
    "CVE-2013-0783"
  );
  script_bugtraq_id(58037, 58038, 58041, 58042, 58043, 58044, 58047);
  script_osvdb_id(90421, 90422, 90423, 90424, 90425, 90429, 90430);

  script_name(english:"Firefox ESR 17.x < 17.0.3 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox ESR 17.x is potentially affected by
the following security issues :

   - Numerous memory safety errors exist. (CVE-2013-0783)

  - An error exists related to Chrome Object Wrappers (COW)
    or System Only Wrappers (SOW) that could allow security
    bypass. (CVE-2013-0773)

  - The file system location of the active browser profile
    could be disclosed and used in further attacks.
    (CVE-2013-0774)

  - A use-after-free error exists in the function
    'nsImageLoadingContent'. (CVE-2013-0775)

  - Spoofing HTTPS URLs is possible due to an error related
    to proxy '407' responses and embedded script code.
    (CVE-2013-0776)

  - A heap-based use-after-free error exists in the function
    'nsOverflowContinuationTracker::Finish'. (CVE-2013-0780)

  - A heap-based buffer overflow error exists in the
    function 'nsSaveAsCharset::DoCharsetConversion'.
    (CVE-2013-0782)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-21/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-24/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-25/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-26/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-27/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-28/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 17.0.3 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (isnull(get_kb_item(kb_base + '/is_esr'))) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'17.0.3', min:'17.0', severity:SECURITY_HOLE);
