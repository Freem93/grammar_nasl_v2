#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39356);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-1690", "CVE-2009-1718");
  script_bugtraq_id(35271, 35272);
  script_osvdb_id(54994, 55414);
  script_xref(name:"Secunia", value:"35411");

  script_name(english:"Google Chrome < 2.0.172.31 WebKit Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 2.0.172.31.  It thus is reportedly affected by multiple issues :

  - A memory corruption issue exists in the way the WebKit
    handles recursion in certain DOM event handlers.
    Successful exploitation of this issue could allow
    arbitrary code execution within the Google Chrome
    sandbox. (CVE-2009-1690)

  - WebKit's handling of drag events is affected by an
    information disclosure issue. (CVE-2009-1718)");
  # http://googlechromereleases.blogspot.com/2009/06/stable-update-2-webkit-security-fixes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e2e95c8");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 2.0.172.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright("This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'2.0.172.31', severity:SECURITY_WARNING);
