#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70717);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/03 21:05:21 $");

  script_cve_id(
    "CVE-2013-1739",
    "CVE-2013-5590",
    "CVE-2013-5591",
    "CVE-2013-5592",
    "CVE-2013-5595",
    "CVE-2013-5597",
    "CVE-2013-5599",
    "CVE-2013-5600",
    "CVE-2013-5601",
    "CVE-2013-5602",
    "CVE-2013-5604"
  );
  script_bugtraq_id(
    62966,
    63405,
    63415,
    63417,
    63418,
    63421,
    63422,
    63423,
    63424,
    63427,
    63428,
    63430
  );
  script_osvdb_id(
    98402,
    99082,
    99083,
    99084,
    99086,
    99087,
    99089,
    99091,
    99092,
    99093,
    99094
  );

  script_name(english:"Mozilla Thunderbird ESR < 17.0.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird ESR");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a mail client that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird ESR is earlier than 17.0.10 and
is, therefore, potentially affected the following vulnerabilities:

  - The implementation of Network Security Services (NSS)
    does not ensure that data structures are initialized,
    which could result in a denial of service or disclosure
    of sensitive information. (2013-1739)

  - Memory issues exist in the browser engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5590, CVE-2013-5591, CVE-2013-5592)

  - Memory issues exist in the JavaScript engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5595, CVE-2013-5602)

  - Multiple use-after-free vulnerabilities exist that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5597, CVE-2013-5599, CVE-2013-5600,
    CVE-2013-5601)

  - A stack-based buffer overflow in
    txXPathNodeUtils::getBaseURI is possible due to
    uninitialized data during XSLT processing.
    (CVE-2013-5604)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-93.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-95.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-96.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-98.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-100.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-101.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird ESR 17.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:TRUE, fix:'17.0.10', severity:SECURITY_HOLE, xss:FALSE);
