#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57468);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/11/13 21:35:39 $");

  script_cve_id("CVE-2011-3919", "CVE-2011-3921", "CVE-2011-3922");
  script_bugtraq_id(51300);
  script_osvdb_id(78148, 78149, 78150);

  script_name(english:"Google Chrome < 16.0.912.75 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 16.0.912.75 and is affected the following vulnerabilities:

  - A heap-based buffer overflow exists related to 'libxml'.
    (CVE-2011-3919)

  - A use-after-free error exists related to animation
    frames. (CVE-2011-3921)

  - A stack-based buffer overflow exists related to glyph
    processing. (CVE-2011-3922)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a890709");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 16.0.912.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'16.0.912.75', severity:SECURITY_HOLE);
