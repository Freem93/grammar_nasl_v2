#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69272);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id(
    "CVE-2013-1701",
    "CVE-2013-1702",
    "CVE-2013-1704",
    "CVE-2013-1705",
    "CVE-2013-1708",
    "CVE-2013-1709",
    "CVE-2013-1710",
    "CVE-2013-1711",
    "CVE-2013-1713",
    "CVE-2013-1714",
    "CVE-2013-1717",
    "CVE-2013-6674",
    "CVE-2014-2018"
  );
  script_bugtraq_id(
    61864,
    61867,
    61871,
    61872,
    61874,
    61875,
    61876,
    61877,
    61882,
    61896,
    61900,
    65158,
    65620
  );
  script_osvdb_id(
    96010,
    96011,
    96012,
    96013,
    96014,
    96017,
    96018,
    96019,
    96020,
    96022,
    96023,
    102566,
    103429
  );
  script_xref(name:"CERT", value:"863369");
  script_xref(name:"EDB-ID", value:"31223");

  script_name(english:"SeaMonkey < 2.20 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of SeaMonkey is a version prior to 2.20. It is,
therefore, potentially affected by the following vulnerabilities :

  - Various errors exist that could allow memory corruption
    conditions. (CVE-2013-1701, CVE-2013-1702)

  - Use-after-free errors exist related to DOM modification
    when using 'SetBody' and generating a 'Certificate
    Request Message'. (CVE-2013-1704, CVE-2013-1705)

  - An error exists in the function 'nsCString::CharAt'
    that could allow application crashes when decoding
    specially crafted WAV audio files. (CVE-2013-1708)

  - Unspecified errors exist related to HTML frames and
    history handling, 'XrayWrappers', JavaScript URI
    handling and web workers using 'XMLHttpRequest' that
    could allow cross-site scripting attacks.
    (CVE-2013-1709, CVE-2013-1711, CVE-2013-1713,
    CVE-2013-1714)

  - An unspecified error exists related to generating
    'Certificate Request Message Format' (CRMF) requests
    that could allow cross-site scripting attacks.
    (CVE-2013-1710)

  - An error exists related to Java applets and 'file:///'
    URIs that could allow read-only access to arbitrary
    files. (CVE-2013-1717)

  - An input validation error exists related to email
    messages containing HTML and iframes and the action of
    replying to or forwarding such messages that could
    allow cross-site scripting attacks. (CVE-2013-6674)

  - An input validation error exists related to email
    messages containing HTML and object or embed elements
    that could allow cross-site scripting attacks.
    (CVE-2014-2018)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-63.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-64.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-65.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-67.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-68.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-69.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-70.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-72.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-73.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-75.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-14.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox toString console.time Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.20', severity:SECURITY_HOLE, xss:TRUE);
