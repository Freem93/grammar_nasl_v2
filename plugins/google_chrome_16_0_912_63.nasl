#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57288);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-3903",
    "CVE-2011-3904",
    "CVE-2011-3905",
    "CVE-2011-3906",
    "CVE-2011-3907",
    "CVE-2011-3908",
    "CVE-2011-3909",
    "CVE-2011-3910",
    "CVE-2011-3911",
    "CVE-2011-3912",
    "CVE-2011-3913",
    "CVE-2011-3914",
    "CVE-2011-3915",
    "CVE-2011-3916",
    "CVE-2011-3917"
  );
  script_bugtraq_id(51041, 51084, 51262);
  script_osvdb_id(
    77706,
    77707,
    77708,
    77709,
    77710,
    77711,
    77712,
    77713,
    77714,
    77715,
    77716,
    77717,
    77718,
    77719,
    77720
  );

  script_name(english:"Google Chrome < 16.0.912.63 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 16.0.912.63 and is affected by the following vulnerabilities:

  - Out-of-bounds read errors exist related to regex
    matching, libxml, the PDF parser, the SVG parser, YUV
    video frame handling, i18n handling in V8 and PDF cross
    references. (CVE-2011-3903, CVE-2011-3905,
    CVE-2011-3906, CVE-2011-3908, CVE-2011-3910,
    CVE-2011-3911, CVE-2011-3914, CVE-2011-3916)

  - Use-after-free errors exist related to SVG filters,
    Range handling and bidi handling. (CVE-2011-3904,
    CVE-2011-3912, CVE-2011-3913)

  - URL bar spoofing is possible due to an error related
    to 'view-source'. (CVE-2011-3907)

  - A memory corruption error exists related to arrays of
    CSS properties. (CVE-2011-3909)

  - A buffer overflow exists related to PDF font handling.
    (CVE-2011-3915)

  - A stack-based buffer overflow exists related to the
    'FileWatcher'. (CVE-2011-3917)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4250c75f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 16.0.912.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'16.0.912.63', severity:SECURITY_HOLE);
