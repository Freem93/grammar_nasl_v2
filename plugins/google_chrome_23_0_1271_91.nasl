#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63063);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/26 05:42:54 $");

  script_cve_id(
    "CVE-2012-5130",
    "CVE-2012-5132",
    "CVE-2012-5133",
    "CVE-2012-5134",
    "CVE-2012-5135",
    "CVE-2012-5136"
  );
  script_bugtraq_id(56684);
  script_osvdb_id(87882, 87884, 87885, 87886, 87887, 87888);

  script_name(english:"Google Chrome < 23.0.1271.91 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 23.0.1271.91 and is, therefore, affected by the following
vulnerabilities :

  - An out-of-bounds read error exists related to 'Skia'.
    (CVE-2012-5130)

  - An unspecified error exists related to chunked encoding
    that can result in application crashes. (CVE-2012-5132)

  - Use-after-free errors exist related to 'SVG' filters
    and printing. (CVE-2012-5133, CVE-2012-5135)

  - A buffer underflow error exists related to 'libxml'.
    (CVE-2012-5134)

  - A cast error exists related to input element handling.
    (CVE-2012-5136)

Successful exploitation of any of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  # http://googlechromereleases.blogspot.com/2012/11/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0938983");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 23.0.1271.91 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/27");

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
google_chrome_check_version(installs:installs, fix:'23.0.1271.91', severity:SECURITY_WARNING);
