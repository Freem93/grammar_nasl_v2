#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66989);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/16 19:43:13 $");

  script_cve_id(
    "CVE-2013-1682",
    "CVE-2013-1683",
    "CVE-2013-1684",
    "CVE-2013-1685",
    "CVE-2013-1686",
    "CVE-2013-1687",
    "CVE-2013-1688",
    "CVE-2013-1690",
    "CVE-2013-1692",
    "CVE-2013-1693",
    "CVE-2013-1694",
    "CVE-2013-1695",
    "CVE-2013-1696",
    "CVE-2013-1697",
    "CVE-2013-1698",
    "CVE-2013-1699"
  );
  script_bugtraq_id(
    60765,
    60766,
    60768,
    60773,
    60774,
    60776,
    60777,
    60778,
    60779,
    60783,
    60784,
    60785,
    60787,
    60788,
    60789,
    60790
  );
  script_osvdb_id(
    94577,
    94578,
    94579,
    94580,
    94581,
    94582,
    94583,
    94584,
    94585,
    94587,
    94588,
    94589,
    94590,
    94591,
    94592,
    94596
  );

  script_name(english:"Firefox < 22.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox is earlier than 22.0 and is,
therefore, potentially affected by multiple vulnerabilities :

  - Various, unspecified memory safety issues exist.
    (CVE-2013-1682, CVE-2013-1683)

  - Heap-use-after-free errors exist related to
    'LookupMediaElementURITable',
    'nsIDocument::GetRootElement' and 'mozilla::ResetDir'.
    (CVE-2013-1684, CVE-2013-1685, CVE-2013-1686)

  - An error exists related to 'XBL scope', 'System Only
    Wrappers' (SOW) and chrome-privileged pages that could
    allow cross-site scripting attacks. (CVE-2013-1687)

  - An error exists related to the 'profiler' that could
    allow arbitrary code execution. (CVE-2013-1688)

  - An error related to 'onreadystatechange' and unmapped
    memory could cause application crashes and allow
    arbitrary code execution. (CVE-2013-1690)

  - The application sends data in the body of XMLHttpRequest
    (XHR) HEAD requests and could aid in cross-site request
    forgery attacks. (CVE-2013-1692)

  - An error related to the processing of SVG content could
    allow a timing attack to disclose information across
    domains. (CVE-2013-1693)

  - An error exists related to 'PreserveWrapper' and the
    'preserved-wrapper' flag that could cause potentially
    exploitable application crashes. (CVE-2013-1694)

  - An error exists related to '<iframe sandbox>'
    restrictions that could allow a bypass of these
    restrictions. (CVE-2013-1695)

  - The 'X-Frame-Options' header is ignored in certain
    situations and can aid in click-jacking attacks.
    (CVE-2013-1696)

  - An error exists related to the 'toString' and 'valueOf'
    methods that could allow 'XrayWrappers' to be bypassed.
    (CVE-2013-1697)

  - An error exists related to the 'getUserMedia'
    permission dialog that could allow a user to be tricked
    into giving access to unintended domains.
    (CVE-2013-1698)

  - Homograph domain spoofing protection is incomplete and
    certain attacks are still possible using
    Internationalized Domain Names (IDN). (CVE-2013-1699)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-52/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-53/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-54/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-55/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-56/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-57/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-58/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-59/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-60/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-61/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 22.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox onreadystatechange Event DocumentViewerImpl Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
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

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'22.0', severity:SECURITY_HOLE, xss:TRUE, xsrf:TRUE);
