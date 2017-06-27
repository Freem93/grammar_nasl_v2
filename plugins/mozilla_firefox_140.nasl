#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60043);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id(
    "CVE-2012-1948",
    "CVE-2012-1949",
    "CVE-2012-1950",
    "CVE-2012-1951",
    "CVE-2012-1952",
    "CVE-2012-1953",
    "CVE-2012-1954",
    "CVE-2012-1955",
    "CVE-2012-1957",
    "CVE-2012-1958",
    "CVE-2012-1959",
    "CVE-2012-1960",
    "CVE-2012-1961",
    "CVE-2012-1962",
    "CVE-2012-1963",
    "CVE-2012-1965",
    "CVE-2012-1966",
    "CVE-2012-1967"
  );
  script_bugtraq_id(
    54572,
    54573,
    54574,
    54575,
    54576,
    54577,
    54578,
    54579,
    54580,
    54582,
    54583,
    54584,
    54585,
    54586
  );
  script_osvdb_id(
    83995,
    83996,
    83997,
    83998,
    83999,
    84000,
    84001,
    84002,
    84003,
    84004,
    84005,
    84006,
    84007,
    84008,
    84009,
    84010,
    84012,
    84013
  );

  script_name(english:"Firefox < 14.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox is earlier than 14.0 and thus, is 
potentially affected by the following security issues :

  - Several memory safety issues exist, some of which could
    potentially allow arbitrary code execution.
    (CVE-2012-1948, CVE-2012-1949)

  - An error related to drag and drop can allow incorrect
    URLs to be displayed. (CVE-2012-1950)

  - Several memory safety issues exist related to the Gecko
    layout engine. (CVE-2012-1951, CVE-2012-1952,
    CVE-2012-1953, CVE-2012-1954)

  - An error related to JavaScript functions
    'history.forward' and 'history.back' can allow
    incorrect URLs to be displayed. (CVE-2012-1955)

  - Cross-site scripting attacks are possible due to an
    error related to the '<embed>' tag within an RSS
    '<description>' element. (CVE-2012-1957)

  - A use-after-free error exists related to the method
    'nsGlobalWindow::PageHidden'. (CVE-2012-1958)

  - An error exists that can allow 'same-compartment
    security wrappers' (SCSW) to be bypassed.
    (CVE-2012-1959)

  - An out-of-bounds read error exists related to the color
    management library (QCMS). (CVE-2012-1960)
  
  - The 'X-Frames-Options' header is ignored if it is
    duplicated. (CVE-2012-1961)

  - A memory corruption error exists related to the method
    'JSDependentString::undepend'. (CVE-2012-1962)

  - An error related to the 'Content Security Policy' (CSP)
    implementation can allow the disclosure of OAuth 2.0
    access tokens and OpenID credentials. (CVE-2012-1963)

  - An error exists related to the 'feed:' URL that can
    allow cross-site scripting attacks. (CVE-2012-1965)

  - Cross-site scripting attacks are possible due to an
    error related to the 'data:' URL and context menus.
    (CVE-2012-1966)

  - An error exists related to the 'javascript:' URL that
    can allow scripts to run at elevated privileges outside
    the sandbox. (CVE-2012-1967)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-42.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-43.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-44.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-45.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-46.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-47.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-48.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-49.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-50.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-51.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-52.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-53.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-55.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-56.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 14.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'14.0', severity:SECURITY_HOLE, xss:TRUE);
