#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58954);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2011-3078",
    "CVE-2011-3079",
    "CVE-2011-3080",
    "CVE-2011-3081",
    "CVE-2012-1521"
  );
  script_bugtraq_id(53309);
  script_osvdb_id(81643, 81644, 81645, 81646, 81647);

  script_name(english:"Google Chrome < 18.0.1025.168 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 18.0.1025.168 and is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist related to floating element
    handling and the xml parser. (CVE-2011-3078,
    CVE-2012-1521, CVE-2011-3081)

  - A validation error exists related to Inter-Process
    Communications (IPC). (CVE-2011-3079)

  - A race condition exists in the method
    'CrossCallParamsEx::CreateFromBuffer' in the file
    'sandbox/src/crosscall_server.cc' and is related to
    sandbox Inter-Process Communication (IPC).
    (CVE-2011-3080)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33461cc2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 18.0.1025.168 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/01");

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
google_chrome_check_version(installs:installs, fix:'18.0.1025.168', severity:SECURITY_HOLE);
