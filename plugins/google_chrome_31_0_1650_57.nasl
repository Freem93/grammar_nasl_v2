#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70923);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/02/04 02:39:10 $");

  script_cve_id("CVE-2013-6632");
  script_bugtraq_id(63729);
  script_osvdb_id(99786);

  script_name(english:"Google Chrome < 31.0.1650.57 Multiple Memory Corruptions");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 31.0.1650.57.  It is, therefore, affected by multiple
unspecified memory corruption vulnerabilities.");
  # http://googlechromereleases.blogspot.com/2013/11/stable-channel-update_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fdac0ce");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 31.0.1650.57 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'31.0.1650.57', severity:SECURITY_HOLE);
