#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90790);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/06 13:21:20 $");

  script_cve_id(
    "CVE-2016-2804",
    "CVE-2016-2806",
    "CVE-2016-2807",
    "CVE-2016-2808",
    "CVE-2016-2811",
    "CVE-2016-2812",
    "CVE-2016-2814",
    "CVE-2016-2816",
    "CVE-2016-2817",
    "CVE-2016-2820"
  );
  script_bugtraq_id(88099, 88100);
  script_osvdb_id(
    137609,
    137610,
    137611,
    137613,
    137614,
    137615,
    137616,
    137617,
    137618,
    137619,
    137620,
    137621,
    137622,
    137623,
    137624,
    137625,
    137626,
    137627,
    137628,
    137629,
    137630,
    137631,
    137632,
    137633,
    137634,
    137636,
    137637,
    137639,
    137640,
    137641,
    137642,
    137643
  );
  script_xref(name:"MFSA", value:"2016-39");
  script_xref(name:"MFSA", value:"2016-42");
  script_xref(name:"MFSA", value:"2016-44");
  script_xref(name:"MFSA", value:"2016-45");
  script_xref(name:"MFSA", value:"2016-46");
  script_xref(name:"MFSA", value:"2016-47");
  script_xref(name:"MFSA", value:"2016-48");

  script_name(english:"Firefox < 46 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 46. It is, therefore, affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    attacker to corrupt memory, resulting in the execution
    of arbitrary code. (CVE-2016-2804, CVE-2016-2806,
    CVE-2016-2807)

  - A flaw exists due to improper validation of
    user-supplied input when handling the 32-bit generation
    count of the underlying HashMap. A context-dependent
    attacker can exploit this to cause a buffer overflow
    condition, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2016-2808)

  - A remote code execution vulnerability exists due to a
    use-after-free error in the BeginReading() function. A
    context-dependent attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-2811)

  - A remote code execution vulnerability exists due to a
    race condition in ServiceWorkerManager in the get()
    function. A context-dependent attacker can exploit this
    to execute arbitrary code. (CVE-2016-2812)

  - A heap buffer overflow condition exists in the Google
    Stagefright component due to improper validation of
    user-supplied input when handling CENC offsets and the
    sizes table. A context-dependent attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-2814)

  - A security bypass vulnerability exists due to the
    Content Security Policy (CSP) not being properly applied
    to web content sent with the 'multipart/x-mixed-replace'
    MIME-type. A context-dependent attacker can exploit this
    to bypass CSP protection. (CVE-2016-2816)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper restriction of unprivileged 'javascript: URL'
    navigation. A context-dependent attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in the context of a user's browser
    session. (CVE-2016-2817)

  - A flaw exists in the Firefox Health Report that is
    triggered when it accepts any content document events
    that are presented in its iframe. A context-dependent
    attacker can exploit this to manipulate sharing
    preferences. (CVE-2016-2820)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-42/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-44/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-45/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-47/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-48/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox version 46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'46', severity:SECURITY_HOLE);
