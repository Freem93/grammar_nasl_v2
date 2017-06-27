#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62518);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2012-2900",
    "CVE-2012-5108",
    "CVE-2012-5109",
    "CVE-2012-5110",
    "CVE-2012-5111"
  );
  script_bugtraq_id(55830);
  script_osvdb_id(86119, 86120, 86121, 86122, 86123);

  script_name(english:"Google Chrome < 22.0.1229.92 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 22.0.1229.92 and is, therefore, affected by the following
vulnerabilities :

  - An unspecified error exists related to Skia text
    rendering can cause the application to crash.
    (CVE-2012-2900)

  - A race condition exists related to audio device
    handling. (CVE-2012-5108)

  - Out-of-bounds read errors exist related to 'ICU'
    regular expressions and the compositor.
    (CVE-2012-5109, CVE-2012-5110)

  - The 'Pepper' plugins are missing crash monitoring.
    (CVE-2012-5111)

Successful exploitation of any of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  # http://googlechromereleases.blogspot.com/2012/10/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ba40430");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 22.0.1229.92 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/12");

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
google_chrome_check_version(installs:installs, fix:'22.0.1229.92', severity:SECURITY_WARNING);
