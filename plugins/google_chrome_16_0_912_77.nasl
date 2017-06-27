#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57666);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-3924",
    "CVE-2011-3925",
    "CVE-2011-3926",
    "CVE-2011-3927",
    "CVE-2011-3928"
  );
  script_bugtraq_id(51641, 52956);
  script_osvdb_id(78543, 78544, 78545, 78546, 78547);

  script_name(english:"Google Chrome < 16.0.912.77 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 16.0.912.77 and is, therefore, affected the following
vulnerabilities:

  - Use-after-free errors exist related to DOM selections,
    DOM handling and Safe Browsing functionality.
    (CVE-2011-3924, CVE-2011-3925, CVE-2011-3928)

  - A heap-based buffer overflow exists in the 'tree
    builder'. (CVE-2011-3926)

  - An error exists related to an uninitialized value in
    'Skia'. (CVE-2011-3927)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-055/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0feecd9f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 16.0.912.77 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/24");

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
google_chrome_check_version(installs:installs, fix:'16.0.912.77', severity:SECURITY_HOLE);
