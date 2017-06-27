#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92792);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2016-5139",
    "CVE-2016-5140",
    "CVE-2016-5141",
    "CVE-2016-5142",
    "CVE-2016-5143",
    "CVE-2016-5144",
    "CVE-2016-5145",
    "CVE-2016-5146"
  );
  script_bugtraq_id(92276);
  script_osvdb_id(
    140273,
    142525,
    142526,
    142527,
    142528,
    142529,
    142530,
    142531,
    142532,
    142627
  );

  script_name(english:"Google Chrome < 52.0.2743.116 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 52.0.2743.116. It is, therefore, affected by multiple
vulnerabilities :

  - An overflow condition exists in PDFium due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service 
    condition or the execution of arbitrary code.
    (CVE-2016-5139)

  - An overflow condition exists in OpenJPEG due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service 
    condition or the execution of arbitrary code.
    (CVE-2016-5140)

  - A flaw exists that is triggered when nested message
    loops access documents without generating a
    notification. An attacker can exploit this to spoof the
    address bar. (CVE-2016-5141)

  - A use-after-free error exists that allows an attacker to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-5142)

  - A flaw exists in the sanitizeRemoteFrontendUrl()
    function in devtools.js due to a failure to properly
    sanitize input parameters. An attacker can exploit this
    to have an unspecified impact. (CVE-2016-5143)

  - A flaw exists in the loadScriptsPromise() function in
    Runtime.js due to a failure to properly sanitize input
    parameters. An attacker can exploit this to have an
    unspecified impact. (CVE-2016-5144)

  - A flaw exists due to improper handling of specially
    crafted images. An attacker can exploit this to bypass
    the same-origin policy. (CVE-2016-5145)

  - Multiple unspecified high and medium severity
    vulnerabilities exist, including an overflow condition
    in WebRTC due to improper validation user-supplied input
    when handling RTP packets. An attacker can exploit this
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2016-5146)

Note that Nessus has not tested for these issues but has instead 
relied only on the application's self-reported version number.");
  # https://googlechromereleases.blogspot.com/2016/08/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81b23127");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 52.0.2743.116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'52.0.2743.116', severity:SECURITY_HOLE);
