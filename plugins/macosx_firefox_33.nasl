#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78470);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2014-1574",
    "CVE-2014-1575",
    "CVE-2014-1576",
    "CVE-2014-1577",
    "CVE-2014-1578",
    "CVE-2014-1580",
    "CVE-2014-1581",
    "CVE-2014-1582",
    "CVE-2014-1583",
    "CVE-2014-1584",
    "CVE-2014-1585",
    "CVE-2014-1586"
  );
  script_bugtraq_id(
    70424,
    70425,
    70426,
    70427,
    70428,
    70430,
    70431,
    70432,
    70434,
    70436,
    70439,
    70440
  );
  script_osvdb_id(
    113141,
    113142,
    113143,
    113144,
    113145,
    113146,
    113147,
    113148,
    113149,
    113150,
    113151,
    113152,
    113159,
    113160,
    113161,
    113162,
    113163,
    113164,
    113165,
    113166,
    113191,
    113192,
    113209
  );

  script_name(english:"Firefox < 33.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is a
version prior to 33.0. It is, therefore, affected by the following
vulnerabilities :

  - Multiple memory safety flaws exist within the browser
    engine. Exploiting these, an attacker can cause a denial
    of service or execute arbitrary code. (CVE-2014-1574,
    CVE-2014-1575)

  - A buffer overflow vulnerability exists when
    capitalization style changes occur during CSS parsing.
    (CVE-2014-1576)

  - An out-of-bounds read error exists in the Web Audio
    component when invalid values are used in custom
    waveforms that leads to a denial of service or
    information disclosure. (CVE-2014-1577)

  - An out-of-bounds write error exists when processing
    invalid tile sizes in 'WebM' format videos that result
    in arbitrary code execution. (CVE-2014-1578)

  - Memory is not properly initialized during GIF rendering
    within a '<canvas>' element. Using a specially crafted
    web script, a remote attacker can exploit this to
    acquire sensitive information from the process memory.
    (CVE-2014-1580)

  - A use-after-free error exists in the
    'DirectionalityUtils' component when text direction is
    used in the text layout that results in arbitrary
    code execution. (CVE-2014-1581)

  - Multiple security bypass vulnerabilities exist related
    to key pinning, a method to prevent man-in-the-middle
    attacks by verifying certificates. An attacker can use
    SPDY or HTTP/2 connection coalescing to bypass key
    pinning on websites that use a domain name that resolve
    to the same IP address. Another issue exists in which
    key pinning verification is not performed due to an
    issue verifying the issuer of an SSL certificate. These
    issues could result in man-in-the-middle attacks. Note
    that key pinning was introduced in Firefox 32.
    (CVE-2014-1582, CVE-2014-1584)

  - An error exists that could allow a malicious app to use
    'AlarmAPI' to read cross-origin references and possibly
    allow for the same-origin policy to be bypassed.
    (CVE-2014-1583)

  - Multiple issues exist in WebRTC when the session is
    running within an 'iframe' element that will allow the
    session to be accessible even when sharing is stopped
    and when returning to the website. This could lead to
    video inadvertently being shared. (CVE-2014-1585,
    CVE-2014-1586)");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-74.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-75.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-76.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-77.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-78.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-79.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-80.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-81.html");
   script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-82.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 33.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'33.0', severity:SECURITY_HOLE, xss:FALSE);
