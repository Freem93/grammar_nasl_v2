#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88459);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/28 20:52:58 $");

  script_cve_id(
    "CVE-2015-7208",
    "CVE-2016-1930",
    "CVE-2016-1931",
    "CVE-2016-1933",
    "CVE-2016-1935",
    "CVE-2016-1937",
    "CVE-2016-1938",
    "CVE-2016-1939",
    "CVE-2016-1941",
    "CVE-2016-1942",
    "CVE-2016-1944",
    "CVE-2016-1945",
    "CVE-2016-1946",
    "CVE-2016-1947",
    "CVE-2016-1978"
  );
  script_bugtraq_id(
    79280
  );
  script_osvdb_id(
    131875,
    133629,
    133630,
    133631,
    133632,
    133633,
    133634,
    133635,
    133636,
    133637,
    133638,
    133639,
    133640,
    133641,
    133642,
    133643,
    133644,
    133645,
    133646,
    133647,
    133648,
    133649,
    133650,
    133651,
    133652,
    133653,
    133654,
    133656,
    133657,
    133659,
    133660,
    133661,
    133662,
    133682,
    133683,
    133684,
    135718
  );
  script_xref(name:"MFSA", value:"2016-01");
  script_xref(name:"MFSA", value:"2016-02");
  script_xref(name:"MFSA", value:"2016-03");
  script_xref(name:"MFSA", value:"2016-04");
  script_xref(name:"MFSA", value:"2016-06");
  script_xref(name:"MFSA", value:"2016-07");
  script_xref(name:"MFSA", value:"2016-08");
  script_xref(name:"MFSA", value:"2016-09");
  script_xref(name:"MFSA", value:"2016-10");
  script_xref(name:"MFSA", value:"2016-11");
  script_xref(name:"MFSA", value:"2016-15");

  script_name(english:"Firefox < 44 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 44. It is, therefore, affected by the following vulnerabilities :

  - A cookie injection vulnerability exists due to illegal
    control characters being stored as cookie values in
    violation of RFC6265. A remote attacker can exploit this
    to inject cookies. (CVE-2015-7208)

  - Multiple unspecified memory corruption issues exist that
    allow a remote attacker to execute arbitrary code.
    (CVE-2016-1930, CVE-2016-1931)

  - An integer overflow condition exists due to improper
    parsing of GIF images during deinterlacing. A remote
    attacker can exploit this, via a specially crafted GIF
    image, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-1933)

  - A buffer overflow condition exists in WebGL that is
    triggered when handling cache out-of-memory error
    conditions. A remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-1935)

  - A content spoofing vulnerability exists due to the
    protocol handler dialog treating double click events as
    two single click events. A remote attacker can exploit
    this to spoof content, allowing the attacker to trick a
    user into performing malicious actions. (CVE-2016-1937)

  - A cryptographic weakness exists in Network Security
    Services (NSS) due to incorrect calculations with
    'mp_div' and 'mp_exptmod'. (CVE-2016-1938)

  - A cookie injection vulnerability exists due to illegal
    control characters being permitted in cookie names. A
    remote attacker can exploit this to inject cookies.
    (CVE-2016-1939)

  - An URL spoofing vulnerability exists due to a flaw that
    is triggered during the handling of a URL that invalid
    for the internal protocol, causing the URL to be pasted
    into the address bar. A remote attacker can exploit this
    spoof URLs, allowing the attacker to trick a
    user into visiting a malicious website. (CVE-2016-1942)

  - An unspecified memory corruption issue exists in the
    ANGLE graphics library implementation. A remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-1944)

  - A wild pointer flaw exists due to improper handling of
    ZIP files. A remote attacker can exploit this, via a
    crafted ZIP file, to have an unspecified impact.
    (CVE-2016-1945)

  - An integer overflow condition exists in the bundled
    version of libstagefright due to improper handling of
    MP4 file metadata. A remote attacker can exploit this
    to execute arbitrary code. (CVE-2016-1946)

  - A flaw exists in the safe browsing feature due to the
    Application Reputation service being unreachable. A
    remote attacker can exploit this to convince a user
    into downloading a malicious executable without being
    warned. (CVE-2016-1947)

  - A use-after-free error exists in Network Security
    Services (NSS) due to improper handling of failed
    allocations during DHE and ECDHE handshakes. An attacker
    can exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code.
    (CVE-2016-1978)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-02/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-04/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-06/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-07/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-08/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-09/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-10/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-15/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox version 44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'44', severity:SECURITY_HOLE);
