#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91351);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2016-1672",
    "CVE-2016-1673",
    "CVE-2016-1674",
    "CVE-2016-1675",
    "CVE-2016-1676",
    "CVE-2016-1677",
    "CVE-2016-1678",
    "CVE-2016-1679",
    "CVE-2016-1680",
    "CVE-2016-1681",
    "CVE-2016-1682",
    "CVE-2016-1683",
    "CVE-2016-1684",
    "CVE-2016-1685",
    "CVE-2016-1686",
    "CVE-2016-1687",
    "CVE-2016-1688",
    "CVE-2016-1689",
    "CVE-2016-1690",
    "CVE-2016-1691",
    "CVE-2016-1692",
    "CVE-2016-1693",
    "CVE-2016-1694",
    "CVE-2016-1695"
  );
  script_osvdb_id(
    137043,
    138796,
    139022,
    139023,
    139024,
    139025,
    139026,
    139027,
    139028,
    139029,
    139030,
    139031,
    139032,
    139033,
    139034,
    139035,
    139036,
    139037,
    139038,
    139039,
    139040,
    139041,
    139042,
    139043,
    139186,
    139187,
    139190,
    139191,
    139192,
    140064
  );
  script_xref(name:"EDB-ID", value:"39961");

  script_name(english:"Google Chrome < 51.0.2704.63 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 51.0.2704.63. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple unspecified flaws exist in extension bindings
    that allow a remote attacker to bypass the same-origin
    policy. No other details are available. (CVE-2016-1672,
    CVE-2016-1676)

  - Multiple unspecified flaws exist in Blink that allow a
    remote attacker to bypass the same-origin policy. No
    other details are available. (CVE-2016-1673,
    CVE-2016-1675)

  - An unspecified flaw exists in Extensions that allows a
    remote attacker to bypass the same-origin policy.
    No other details are available. (CVE-2016-1674)

  - An unspecified type confusion error exists in V8
    decodeURI that allows a remote attacker to disclose
    potentially sensitive information. (CVE-2016-1677)

  - A heap buffer overflow condition exists in V8 due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1678)

  - A heap use-after-free error exists in V8 bindings that
    allows a remote attacker to deference already freed
    memory and execute arbitrary code. (CVE-2016-1679)

  - A heap use-after-free error exists in Google Skia that
    allows a remote attacker to deference already freed
    memory and execute arbitrary code. (CVE-2016-1680)

  - A buffer overflow condition exists in OpenJPEG in the
    opj_j2k_read_SPCod_SPCoc() function within file j2k.c
    due to improper validation of user-supplied input. A
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-1681)

  - An unspecified flaw exists in ServiceWorker that allows
    a remote attacker to bypass the Content Security Policy
    (CSP). No other details are available. (CVE-2016-1682)

  - An unspecified out-of-bounds access error exists in
    libxslt that allows a remote attacker to have an
    unspecified impact. (CVE-2016-1683)

  - An integer overflow condition exists in libxslt that
    allows a remote attacker to have an unspecified impact.
    (CVE-2016-1684)

  - Multiple out-of-bounds read errors exist in PDFium that
    allow a remote attacker to cause a denial of service
    condition or disclose potentially sensitive information.
    (CVE-2016-1685, CVE-2016-1686)

  - An unspecified flaw exists in Extensions that allows a
    remote attacker to disclose potentially sensitive
    information. No other details are available.
    (CVE-2016-1687)

  - An out-of-bounds read error exists in V8 that allows a
    remote attacker to cause a denial of service condition
    or disclose potentially sensitive information.
    (CVE-2016-1688)

  - A heap buffer overflow condition exists in Media due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2016-1689)

  - A heap use-after-free error exists in Autofill that
    allows a remote attacker to execute arbitrary code.
    (CVE-2016-1690)

  - A heap buffer overflow condition exists in Google Skia
    due to improper validation of user-supplied input. A
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-1691)

  - An unspecified flaw exists in ServiceWorker that allows
    a remote attacker to carry out a limited bypass of the
    same-origin policy. No other details are available.
    (CVE-2016-1692)

  - A flaw exists due to the Software Removal Tool being
    downloaded over an HTTP connection. A man-in-the-middle
    attacker can exploit this to manipulate its contents.
    (CVE-2016-1693)

  - A unspecified flaw exists that is triggered when HTTP
    Public Key Pinning (HPKP) pins are removed when clearing
    the cache. No other details are available.
    (CVE-2016-1694)

  - Multiple unspecified issues exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-1695)

  - A use-after-free error exists in 'MailboxManagerImpl'
    that is triggered when handling GPU commands. A remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (VulnDB 140064)");
  # http://googlechromereleases.blogspot.com/2016/05/stable-channel-update_25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4d6f0fa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 51.0.2704.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/27");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'51.0.2704.63', severity:SECURITY_HOLE);
