#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64813);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2013-0879",
    "CVE-2013-0880",
    "CVE-2013-0881",
    "CVE-2013-0882",
    "CVE-2013-0883",
    "CVE-2013-0884",
    "CVE-2013-0885",
    "CVE-2013-0887",
    "CVE-2013-0888",
    "CVE-2013-0889",
    "CVE-2013-0890",
    "CVE-2013-0891",
    "CVE-2013-0892",
    "CVE-2013-0893",
    "CVE-2013-0894",
    "CVE-2013-0896",
    "CVE-2013-0897",
    "CVE-2013-0898",
    "CVE-2013-0899",
    "CVE-2013-0900",
    "CVE-2013-2268"
  );
  script_bugtraq_id(
    58167,
    58318,
    59326,
    59327,
    59328,
    59330,
    59331,
    59332,
    59334,
    59336,
    59337,
    59338,
    59339,
    59340,
    59342,
    59343,
    59344,
    59345,
    59346,
    59347,
    59351
  );
  script_osvdb_id(
    101163,
    101164,
    101165,
    101166,
    101167,
    101168,
    90521,
    90522,
    90523,
    90524,
    90525,
    90526,
    90527,
    90529,
    90530,
    90531,
    90532,
    90533,
    90534,
    90535,
    90536,
    90538,
    90539,
    90540,
    90541,
    90542,
    90663,
    90950
  );

  script_name(english:"Google Chrome < 25.0.1364.97 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a
version prior to 25.0.1364.97. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified memory corruption error exists related
    to 'web audio node'. (CVE-2013-0879)

  - Use-after-free errors exist related to database and
    URL handling. (CVE-2013-0880, CVE-2013-0898)

  - Improper memory read errors exist related to Matroska,
    excessive SVG parameters, and Skia. (CVE-2013-0881,
    CVE-2013-0882, CVE-2013-0883, CVE-2013-0888)

  - An error exists related to improper loading of 'NaCl'.
    (CVE-2013-0884)

  - The 'web store' is granted too many API permissions.
    (CVE-2013-0885)

  - The developer tools process is granted too many
    permissions and trusts remote servers incorrectly.
    (CVE-2013-0887)

  - User gestures are not properly checked with respect to
    dangerous file downloads. (CVE-2013-0889)

  - An unspecified memory safety issue exists in the IPC
    layer. (CVE-2013-0890)

  - Integer overflow errors exist related to blob and
    'Opus' handling. (CVE-2013-0891, CVE-2013-0899)

  - Numerous, unspecified, lower-severity issues exist
    related to the IPC layer. (CVE-2013-0892)

  - Race conditions exist related to media handling and
    ICU. (CVE-2013-0893, CVE-2013-0900)

  - A buffer overflow exists related to vorbis decoding.
    (CVE-2013-0894)

  - Memory management errors exist related to plugin
    message handling. (CVE-2013-0896)

  - An off-by-one read error exists related to PDF
    handling. (CVE-2013-0897)

Note that the vendor states that WebKit's MathML implementation has been
disabled in this release.  This is due to several unspecified, high
severity security issues.  Successful exploitation of some of these
issues could lead to an application crash or even allow arbitrary code
execution, subject to the user's privileges.");
  # http://googlechromereleases.blogspot.com/2013/02/stable-channel-update_21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8353dc1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 25.0.1364.97 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

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

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'25.0.1364.97', severity:SECURITY_WARNING);
