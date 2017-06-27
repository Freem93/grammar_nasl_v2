#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38791);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/11/13 21:35:39 $");

  script_cve_id("CVE-2009-0945");
  script_bugtraq_id(34924);
  script_osvdb_id(54500);

  script_name(english:"Google Chrome < 1.0.154.65 WebKit SVGList Object Handling Memory Corruption");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.65. Such versions are reportedly affected by a memory
corruption issue. An attacker could exploit this flaw in order to run
arbitrary code inside the Google Chrome sandbox.");
  # http://googlechromereleases.blogspot.com/2009/05/stable-update-bug-fix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f85eff6");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 1.0.154.65 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright("This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'1.0.154.65', severity:SECURITY_WARNING);
