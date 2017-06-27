#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70273);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id(
    "CVE-2013-2906",
    "CVE-2013-2907",
    "CVE-2013-2908",
    "CVE-2013-2909",
    "CVE-2013-2910",
    "CVE-2013-2911",
    "CVE-2013-2912",
    "CVE-2013-2913",
    "CVE-2013-2914",
    "CVE-2013-2915",
    "CVE-2013-2916",
    "CVE-2013-2917",
    "CVE-2013-2918",
    "CVE-2013-2919",
    "CVE-2013-2920",
    "CVE-2013-2921",
    "CVE-2013-2922",
    "CVE-2013-2923",
    "CVE-2013-2924"
  );
  script_bugtraq_id(62752, 62968);
  script_osvdb_id(
    96406,
    96950,
    96951,
    96952,
    96953,
    96954,
    97966,
    97967,
    97968,
    97970,
    97971,
    97972,
    97973,
    97974,
    97975,
    97976,
    97977,
    97978,
    97979,
    97980,
    97981,
    97982,
    97992,
    97993,
    97994,
    97995,
    97996,
    97997,
    97998,
    97999,
    98000,
    98001,
    98002,
    98003,
    98004,
    98005,
    98006,
    98007,
    98008,
    98009,
    98010,
    98011,
    98012,
    98013,
    98014,
    98024
  );

  script_name(english:"Google Chrome < 30.0.1599.66 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 30.0.1599.66.  It is, therefore, affected by multiple
vulnerabilities :

  - A race condition exists related to 'Web Audio'.
    (CVE-2013-2906)

  - Out-of-bounds read errors exist related to
    the 'Window.prototype' object, 'Web Audio', and URL
    parsing. (CVE-2013-2907, CVE-2013-2917, CVE-2013-2920)

  - Several errors exist related to the address bar that
    could allow spoofing attacks. (CVE-2013-2908,
    CVE-2013-2915, CVE-2013-2916)

  - Use-after-free errors exist related to 'inline-block'
    rendering, 'Web Audio', XSLT, PPAPI, XML document
    parsing, Windows color chooser dialog, DOM, the
    resource loader, the 'template' element and ICU.
    (CVE-2013-2909, CVE-2013-2910, CVE-2013-2911,
    CVE-2013-2912, CVE-2013-2913, CVE-2013-2914,
    CVE-2013-2918, CVE-2013-2921, CVE-2013-2922,
    CVE-2013-2924)

  - A memory corruption error exists in the V8
    JavaScript engine. (CVE-2013-2919)

  - Various, unspecified errors exist. (CVE-2013-2923)");
  # http://googlechromereleases.blogspot.com/2013/10/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e1731d9");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 30.0.1599.66 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'30.0.1599.66', severity:SECURITY_WARNING);
