#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66813);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2013-2854",
    "CVE-2013-2855",
    "CVE-2013-2856",
    "CVE-2013-2857",
    "CVE-2013-2858",
    "CVE-2013-2859",
    "CVE-2013-2860",
    "CVE-2013-2861",
    "CVE-2013-2862",
    "CVE-2013-2863",
    "CVE-2013-2864",
    "CVE-2013-2865"
  );
  script_bugtraq_id(
    60395,
    60396,
    60397,
    60398,
    60399,
    60400,
    60401,
    60402,
    60403,
    60404,
    60405,
    60406
  );
  script_osvdb_id(
    93840,
    93841,
    93842,
    93843,
    93844,
    93845,
    93846,
    93847,
    93848,
    93849,
    93850,
    93899,
    93900,
    93901,
    93902,
    93908,
    93914
  );

  script_name(english:"Google Chrome < 27.0.1453.110 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 27.0.1453.110 and is, therefore, affected by the following
vulnerabilities :

  - An error exists related to the renderer and bad
    handles. (CVE-2013-2854)

  - Errors exist related to dev tools API, Skia GPU
    handling and SSL socket handling that could result in
    memory corruption. (CVE-2013-2855, CVE-2013-2862,
    CVE-2013-2863)

  - Use-after-free errors exist related to input and image
    handling, HTML5 audio, workers accessing database APIs
    and SVG processing. (CVE-2013-2856, CVE-2013-2857,
    CVE-2013-2858, CVE-2013-2860, CVE-2013-2861)

  - An unspecified error exists that could allow cross-
    origin namespace pollution. (CVE-2013-2859)

  - An error exists in the PDF viewer that could allow bad
    free operations. (CVE-2013-2864)

  - The vendor reports various, unspecified errors exist.
    (CVE-2013-2865)");
  # http://googlechromereleases.blogspot.com/2013/06/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9337416");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 27.0.1453.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

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
google_chrome_check_version(installs:installs, fix:'27.0.1453.110', severity:SECURITY_HOLE, xss:TRUE);
