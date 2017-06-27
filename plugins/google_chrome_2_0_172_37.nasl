#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39852);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-1692", "CVE-2009-2555", "CVE-2009-2556");
  script_bugtraq_id(35446, 35722, 35723);
  script_osvdb_id(55242, 55939, 56245);
  script_xref(name:"Secunia", value:"35844");

  script_name(english:"Google Chrome < 2.0.172.37 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 2.0.172.37.  Such versions are reportedly affected by multiple
issues :

  - A heap overflow exists when evaluating specially crafted
    regular expressions in JavaScript. This could lead to a
    denial of service or the execution of arbitrary code
    within the Google Chrome sandbox. (Issue 14719)

  - A memory corruption issue exists in the renderer process
    that could cause a denial of service or possibly allow
    arbitrary code execution with the privileges of the
    logged on user. (CVE-2009-2556)

  - Creating a Select object with a very large length can
    result in memory exhaustion, causing a denial of service.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/504969/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f3cdeb6");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 2.0.172.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/17");

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
google_chrome_check_version(installs:installs, fix:'2.0.172.37', severity:SECURITY_HOLE);
