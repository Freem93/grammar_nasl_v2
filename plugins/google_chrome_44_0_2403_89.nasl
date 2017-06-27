#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84921);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2015-1270",
    "CVE-2015-1271",
    "CVE-2015-1272",
    "CVE-2015-1273",
    "CVE-2015-1274",
    "CVE-2015-1275",
    "CVE-2015-1276",
    "CVE-2015-1277",
    "CVE-2015-1278",
    "CVE-2015-1279",
    "CVE-2015-1280",
    "CVE-2015-1281",
    "CVE-2015-1282",
    "CVE-2015-1283",
    "CVE-2015-1284",
    "CVE-2015-1285",
    "CVE-2015-1286",
    "CVE-2015-1287",
    "CVE-2015-1288",
    "CVE-2015-1289"
  );
  script_bugtraq_id(75973);
  script_osvdb_id(
    120535,
    122300,
    122376,
    122864,
    125001,
    125056,
    125057,
    125058,
    125059,
    125060,
    125061,
    125062,
    125063,
    125064,
    125065,
    125066,
    125067,
    125068,
    125069,
    125070,
    125071,
    125072,
    125073,
    125081,
    125082,
    125083,
    125084,
    125085,
    125086,
    125087,
    125088,
    125089,
    125090,
    125091,
    125092,
    125093,
    125094,
    125095
  );

  script_name(english:"Google Chrome < 44.0.2403.89 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 44.0.2403.89. It is, therefore, affected by multiple
vulnerabilities  :

  - An uninitialized memory read flaw exists in ICU that an
    attacker can exploit to have unspecified impact.
    (CVE-2015-1270)

  - A heap buffer overflow condition exists in PDFium due to
    improper validation of user-supplied input. An attacker
    can exploit this to execute arbitrary code or cause a
    denial of service. (CVE-2015-1271, CVE-2015-1273)

  - A use-after-free memory error exists when the GPU
    process is unexpectedly terminated. An attacker can
    exploit this to have an unspecified impact.
    (CVE-2015-1272)

  - The settings for automatic downloading of files allows
    EXE files to be auto-opened, which can result in the
    execution of malicious code. (CVE-2015-1274)

  - A universal cross-site scripting (UXSS) vulnerability
    exists in Google Chrome for Android due to improper
    validation of 'intent://' URLs. An attacker, using a
    specially crafted request, can exploit this to execute
    arbitrary script code. (CVE-2015-1275)

  - A use-after-free memory error exists in IndexedDB that
    can allow an attacker to execute arbitrary code.
    (CVE-2015-1276)

  - A denial of service vulnerability exists due to a
    use-after-free memory error in the method
    ui::AXTree::Unserialize. An attacker can exploit this to
    cause a crash. (CVE-2015-1277)

  - An unspecified flaw exists when handling PDF files that
    allows an attacker to spoof URLs. (CVE-2015-1278)

  - An integer overflow condition exists in the method
    CJBig2_Image::expand() in file JBig2_Image.cpp due to
    improper validation of user-supplied input. An attacker
    can exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service or the execution of
    arbitrary code. (CVE-2015-1279)

  - A flaw exists in Google Skia due to improper validation
    of user-supplied input, which an attacker can exploit to
    corrupt memory or execute arbitrary code.
    (CVE-2015-1280)

  - An unspecified flaw exists that allows an attacker to
    bypass the Content Security Policy. (CVE-2015-1281)

  - A use-after-free memory error exists in PDFium in the
    file javascript/Document.cpp. An attacker, using a
    crafted file, can exploit this to execute arbitrary
    code. (CVE-2015-1282)

  - A heap buffer overflow condition exists in 'expat'.
    No other information is available. (CVE-2015-1283)

  - A use-after-free memory error exists in Blink that can
    allow an attacker to execute arbitrary code.
    (CVE-2015-1284)

  - An unspecified flaw exists in the XSS auditor that
    allows an attacker to gain access to sensitive
    information. (CVE-2015-1285)

  - A universal cross-site scripting (UXSS) vulnerability
    exists in Blink due to improper validation of
    unspecified input. An attacker, using a crafted request,
    can exploit this to execute arbitrary script code.
    (CVE-2015-1286)

  - A flaw exists in WebKit related to the handling of
    the quirks-mode exception for CSS MIME types, which
    allows an attacker to bypass the cross-origin policy.
    (CVE-2015-1287)

  - A flaw exists in file spellcheck_hunspell_dictionary.cc,
    related to the downloading of spellchecker dictionaries
    over HTTP, which allows a man-in-the-middle to corrupt
    the downloaded dictionaries. (CVE-2015-1288)

  - Multiple vulnerabilities exist that were disclosed by
    internal auditing, fuzzing, and other initiatives,
    which can result in a denial of service, execution of
    arbitrary code, or other moderate to severe impact.
    (CVE-2015-1289)");
  # http://googlechromereleases.blogspot.com/2015/07/stable-channel-update_21.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?50bc47d5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 44.0.2403.89 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/02/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'44.0.2403.89', severity:SECURITY_HOLE, xss:TRUE);
