#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56391);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-2876",
    "CVE-2011-2877",
    "CVE-2011-2878",
    "CVE-2011-2879",
    "CVE-2011-2880",
    "CVE-2011-2881",
    "CVE-2011-3873"
  );
  script_bugtraq_id(49938);
  script_osvdb_id(76061, 76062, 76063, 76064, 76065, 76066, 76067);

  script_name(english:"Google Chrome < 14.0.835.202 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 14.0.835.202.  It therefore is potentially affected by the
following vulnerabilities :

  - Use-after-free errors exist that are related to text
    line box handling and the v8 JavaScript engine
    bindings. (CVE-2011-2876, CVE-2011-2880)

  - An unspecified error exists related to stale fonts in
    SVG text handling. (CVE-2011-2877)

  - A cross-origin violation error exists that could allow
    access to the window prototype. (CVE-2011-2878)

  - Lifetime and threading errors exist that are related to
    audio node handling. (CVE-2011-2879)

  - Unspecified errors related to hidden v8 objects and
    shader translators exist that could allow memory
    corruption. (CVE-2011-2881, CVE-2011-3873)");
  # http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f63d24f5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 14.0.835.202 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/05");

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
google_chrome_check_version(installs:installs, fix:'14.0.835.202', severity:SECURITY_HOLE);
