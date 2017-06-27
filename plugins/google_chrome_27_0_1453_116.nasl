#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66930);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/09/29 17:44:28 $");

  script_cve_id("CVE-2013-2866");
  script_osvdb_id(94411);

  script_name(english:"Google Chrome < 27.0.1453.116 Flash Click-Jacking");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a click-
jacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 27.0.1453.116 and is, therefore, affected by a click-jacking
vulnerability due to the embedded Flash plugin.");
  # Google Translate link to research post
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6fc9135");
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/p/chromium/issues/detail?id=249335");
  # http://googlechromereleases.blogspot.com/2013/06/stable-channel-update_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba4cc044");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 27.0.1453.116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

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
google_chrome_check_version(installs:installs, fix:'27.0.1453.116', severity:SECURITY_WARNING);
