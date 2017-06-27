#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39492);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2009-2121");
  script_bugtraq_id(35462, 35463);
  script_osvdb_id(55278, 59044);
  script_xref(name:"Secunia", value:"35548");

  script_name(english:"Google Chrome < 2.0.172.33 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 2.0.172.33.  Such versions are reportedly affected by multiple
issues :

  - A buffer overflow caused by handling unspecified HTTP
    responses.  This could lead to a denial of service or
    execution of arbitrary code. (CVE-2009-2121)

  - A denial of service caused by SSL renegotiation.  This could
    cause the browser to crash.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=13226");
  # http://googlechromereleases.blogspot.com/2009/06/stable-beta-update-security-fix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0bfaa8f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 2.0.172.33 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright("This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'2.0.172.33', severity:SECURITY_HOLE);
