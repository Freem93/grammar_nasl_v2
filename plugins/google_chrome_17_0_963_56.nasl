#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57974);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2011-3015",
    "CVE-2011-3016",
    "CVE-2011-3017",
    "CVE-2011-3018",
    "CVE-2011-3019",
    "CVE-2011-3020",
    "CVE-2011-3021",
    "CVE-2011-3022",
    "CVE-2011-3023",
    "CVE-2011-3024",
    "CVE-2011-3025",
    "CVE-2011-3026",
    "CVE-2011-3027"
  );
  script_bugtraq_id(52031, 52049);
  script_osvdb_id(
    79283,
    79284,
    79285,
    79286,
    79287,
    79288,
    79289,
    79290,
    79291,
    79292,
    79293,
    79294,
    79295
  );

  script_name(english:"Google Chrome < 17.0.963.56 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 17.0.963.56 and is, therefore, affected by the following
vulnerabilities:

  - Integer overflow errors exist related to PDF codecs and
    libpng. (CVE-2011-3015, CVE-2011-3026)

  - A read-after-free error exists related to 'counter
    nodes'. (CVE-2011-3016)

  - Use-after-free errors exist related to database
    handling, subframe loading, and drag-and-drop
    functionality. (CVE-2011-3017, CVE-2011-3021,
    CVE-2011-3023)

  - Heap-overflow errors exist related to path rendering and
    'MKV' handling. (CVE-2011-3018, CVE-2011-3019)

  - Unspecified errors exist related to the native
    client validator and HTTP use with translation scripts.
    (CVE-2011-3020, CVE-2011-3022)

  - Empty x509 certificates can cause browser crashes.
    (CVE-2011-3024)

  - An out-of-bounds read error exists related to h.264
    parsing. (CVE-2011-3025)

  - A bad variable cast exists related to column handling.
    (CVE-2011-3027)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f5d2c3f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 17.0.963.56 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'17.0.963.56', severity:SECURITY_HOLE);
