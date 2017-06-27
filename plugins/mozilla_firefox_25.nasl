#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70716);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/30 21:51:49 $");

  script_cve_id(
    "CVE-2013-1739",
    "CVE-2013-5590",
    "CVE-2013-5591",
    "CVE-2013-5592",
    "CVE-2013-5593",
    "CVE-2013-5595",
    "CVE-2013-5596",
    "CVE-2013-5597",
    "CVE-2013-5598",
    "CVE-2013-5599",
    "CVE-2013-5600",
    "CVE-2013-5601",
    "CVE-2013-5602",
    "CVE-2013-5603",
    "CVE-2013-5604"
  );
  script_bugtraq_id(
    62966,
    63405,
    63415,
    63416,
    63417,
    63418,
    63419,
    63420,
    63421,
    63422,
    63423,
    63424,
    63427,
    63428,
    63429,
    63430
  );
  script_osvdb_id(
    98402,
    99082,
    99083,
    99084,
    99085,
    99086,
    99087,
    99088,
    99089,
    99090,
    99091,
    99092,
    99093,
    99094,
    99095
  );

  script_name(english:"Firefox < 25.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox is earlier than 25.0 and is,
therefore, potentially affected by the following vulnerabilities :

  - The implementation of Network Security Services (NSS)
    does not ensure that data structures are initialized,
    which could result in a denial of service or disclosure
    of sensitive information. (2013-1739)

  - Memory issues exist in the browser engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5590, CVE-2013-5591, CVE-2013-5592)

  - Arbitrary HTML content can be put into 'select'
    elements.  This can be used to spoof the displayed
    address bar, leading to clickjacking and other spoofing
    attacks. (CVE-2013-5593)

  - Memory issues exist in the JavaScript engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5595, CVE-2013-5602)

  - A race condition exists during image collection on large
    web pages that could result in a denial of service or
    arbitrary code execution. (CVE-2013-5596)

  - Multiple use-after-free vulnerabilities exist that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5597, CVE-2013-5599, CVE-2013-5600,
    CVE-2013-5601, CVE-2013-5603)

  - Improper handling of the 'IFRAME' element in PDF.js
    could result in reading arbitrary files and arbitrary
    JavaScript code execution. (CVE-2013-5598)

  - A stack-based buffer overflow in
    txXPathNodeUtils::getBaseURI is possible due to
    uninitialized data during XSLT processing.
    (CVE-2013-5604)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-93.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-94.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-95.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-96.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-97.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-98.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-99.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-100.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-101.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-102.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 25.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'25.0', severity:SECURITY_HOLE, xss:FALSE);
