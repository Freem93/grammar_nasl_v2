#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61774);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/18 13:46:58 $");

  script_cve_id(
    "CVE-2012-2865",
    "CVE-2012-2866",
    "CVE-2012-2867",
    "CVE-2012-2868",
    "CVE-2012-2869",
    "CVE-2012-2870",
    "CVE-2012-2871",
    "CVE-2012-2872"
  );
  script_bugtraq_id(55331);
  script_osvdb_id(
    85030,
    85031,
    85032,
    85033,
    85034,
    85035,
    85036,
    85037,
    91608
  );

  script_name(english:"Google Chrome < 21.0.1180.89 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 21.0.1180.89 and is, therefore, affected by the following
vulnerabilities :

  - An out-of-bounds read error exists related to
    line-breaking. (CVE-2012-2865)

  - Variable casting errors exist related to 'run-ins' and
    XSL transformations. (CVE-2012-2866, CVE-2012-2871)

  - An unspecified error exists related to the SPDY
    protocol that can result in application crashes.
    (CVE-2012-2867)

  - A unspecified race condition exists related to
    'workers' and XHR. (CVE-2012-2868)

  - An unspecified error exists related to stale buffers
    and URL loading. (CVE-2012-2869)

  - Memory management issues exist related to XPath
    processing. (CVE-2012-2870)

  - Cross-site scripting is possible during the SSL
    interstitial process. (CVE-2012-2872)

Successful exploitation of any of these issues could lead to an
application crash or arbitrary code execution, subject to the user's
privileges.");
  # http://googlechromereleases.blogspot.com/2012/08/stable-channel-update_30.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?834ca1de");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 21.0.1180.89 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'21.0.1180.89', severity:SECURITY_WARNING, xss:TRUE);
