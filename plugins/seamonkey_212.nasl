#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61718);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id(
    "CVE-2012-1956",
    "CVE-2012-1970",
    "CVE-2012-1971",
    "CVE-2012-1972",
    "CVE-2012-1973",
    "CVE-2012-1974",
    "CVE-2012-1975",
    "CVE-2012-1976",
    "CVE-2012-3956",
    "CVE-2012-3957",
    "CVE-2012-3958",
    "CVE-2012-3959",
    "CVE-2012-3960",
    "CVE-2012-3961",
    "CVE-2012-3962",
    "CVE-2012-3963",
    "CVE-2012-3964",
    "CVE-2012-3966",
    "CVE-2012-3968",
    "CVE-2012-3969",
    "CVE-2012-3970",
    "CVE-2012-3971",
    "CVE-2012-3972",
    "CVE-2012-3975",
    "CVE-2012-3976",
    "CVE-2012-3978",
    "CVE-2012-4930"
  );
  script_bugtraq_id(
    55249,
    55260,
    55264,
    55266,
    55274,
    55276,
    55278,
    55292,
    55304,
    55306,
    55310,
    55311,
    55313,
    55314,
    55316,
    55317,
    55318,
    55319,
    55320,
    55321,
    55322,
    55323,
    55324,
    55325,
    55340,
    55341,
    55342,
    55707
  );
  script_osvdb_id(
    84959,
    84960,
    84961,
    84962,
    84963,
    84964,
    84965,
    84968,
    84969,
    84970,
    84971,
    84972,
    84973,
    84974,
    84975,
    84989,
    84990,
    84992,
    84993,
    84995,
    84996,
    84997,
    84999,
    85000,
    85001,
    85004,
    85926
  );

  script_name(english:"SeaMonkey < 2.12.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of SeaMonkey is earlier than 2.12.0. Such
versions are potentially affected by the following security issues :

  - An error exists related to 'Object.defineProperty'
    and the location object that could allow cross-site
    scripting attacks. (CVE-2012-1956)

  - Unspecified memory safety issues exist. (CVE-2012-1970,
    CVE-2012-1971)

  - Multiple use-after-free errors exist. (CVE-2012-1972,
    CVE-2012-1973, CVE-2012-1974, CVE-2012-1975,
    CVE-2012-1976, CVE-2012-3956, CVE-2012-3957,
    CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
    CVE-2012-3961, CVE-2012-3962, CVE-2012-3963,
    CVE-2012-3964)

  - An error exists related to bitmap (BMP) and icon (ICO)
    file decoding that can lead to memory corruption,
    causing application crashes and potentially arbitrary
    code execution. (CVE-2012-3966)

  - A use-after-free error exists related to WebGL shaders.
    (CVE-2012-3968)

  - A buffer overflow exists related to SVG filters.
    (CVE-2012-3969)

  - A use-after-free error exists related to elements
    having 'requiredFeatures' attributes. (CVE-2012-3970)

  - A 'Graphite 2' library memory corruption error exists.
    (CVE-2012-3971)

  - An XSLT out-of-bounds read error exists related to
    'format-number'. (CVE-2012-3972)

  - The DOM parser can unintentionally load linked
    resources in extensions. (CVE-2012-3975)

  - Incorrect SSL certificate information can be displayed
    in the address bar when two 'onLocationChange' events
    fire out of order. (CVE-2012-3976)

  - Security checks related to location objects can be
    bypassed if crafted calls are made to the browser
    chrome code. (CVE-2012-3978)

  - SPDY's request header compression leads to information
    leakage, which can allow private data such as session
    cookies to be extracted, even over an SSL connection.
    (CVE-2012-4930)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524145/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-57.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-58.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-59.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-61.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-62.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-63.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-64.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-65.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-68.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-69.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-70.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-73.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.12.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.12.0', severity:SECURITY_HOLE, xss:TRUE);
