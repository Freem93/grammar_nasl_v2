#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70916);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2013-2931",
    "CVE-2013-6621",
    "CVE-2013-6622",
    "CVE-2013-6623",
    "CVE-2013-6624",
    "CVE-2013-6625",
    "CVE-2013-6626",
    "CVE-2013-6627",
    "CVE-2013-6629",
    "CVE-2013-6628",
    "CVE-2013-6630",
    "CVE-2013-6631"
  );
  script_bugtraq_id(
    63667,
    63669,
    63670,
    63671,
    63672,
    63673,
    63674,
    63675,
    63676,
    63677,
    63678,
    63679
  );
  script_osvdb_id(
    99707,
    99708,
    99709,
    99710,
    99711,
    99712,
    99713,
    99714,
    99715,
    99716,
    99717,
    99718,
    99719,
    99720,
    99721,
    99722,
    99724,
    99725,
    99726,
    99727,
    99728,
    99729,
    99730,
    99746
  );

  script_name(english:"Google Chrome < 31.0.1650.48 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 31.0.1650.48.  It is, therefore, affected by multiple
vulnerabilities :

  - Various, unspecified errors exist. (CVE-2013-2931)

  - Use-after-free errors exist related to speech input
    elements, media elements, 'id' attribute strings, DOM
    ranges, and libjingle. (CVE-2013-6621, CVE-2013-6622,
    CVE-2013-6624, CVE-2013-6625, CVE-2013-6631)

  - Out-of-bounds read errors exist in SVG and HTTP
    parsing. (CVE-2013-6623, CVE-2013-6627)

  - An address bar URI-spoofing vulnerability exists that
    is related to interstitial warnings. (CVE-2013-6626)

  - A certificate validation security bypass issue exists
    during TLS renegotiation. (CVE-2013-6628)

  - A memory corruption error exists in the libjpeg and
    libjpeg-turbo libraries when memory is uninitialized
    when decoding images with missing SOS data.
    (CVE-2013-6629)

  - A memory corruption error exists in the 'jdmarker.c'
    source file in the libjpeg-turbo library when processing
    Huffman tables. (CVE-2013-6630)");

  # http://googlechromereleases.blogspot.com/2013/11/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0a7b53d");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 31.0.1650.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

# Check each installation.
get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'31.0.1650.48', severity:SECURITY_HOLE);
