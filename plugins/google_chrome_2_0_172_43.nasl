#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40778);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2009-2414", "CVE-2009-2416", "CVE-2009-2935");
  script_bugtraq_id(36010, 36149);
  script_osvdb_id(56985, 56990, 57421, 57422);
  script_xref(name:"Secunia", value:"36207");
  script_xref(name:"Secunia", value:"36417");

  script_name(english:"Google Chrome < 2.0.172.43 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 2.0.172.43.  Such versions are reportedly affected by multiple
issues :

  - A flaw in the V8 JavaScript engine might allow a
    specially crafted JavaScript page to access
    unauthorized data in memory or to execute arbitrary code
    within the Google Chrome sandbox. (CVE-2009-2935)

  - The browser can connect to SSL-enabled sites whose
    certificates use weak hash algorithms, such as MD2 and
    MD4. An attacker may be able exploit this issue to
    forge certificates and spoof an invalid website as a
    valid HTTPS site. (Issue #18725)

  - A stack consumption vulnerability in libxml2 library
    could be exploited to crash the Google Chrome tab process
    or execute arbitrary code with in Google Chrome sandbox.
    (CVE-2009-2414)

  - Multiple use-after-free vulnerabilities in libxml2
    library could be exploited to crash the Google Chrome
    tab process or execute arbitrary code with in Google
    Chrome sandbox. (CVE-2009-2416)");

  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=18639");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=18725");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3047265");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 2.0.172.43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/26");

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
google_chrome_check_version(installs:installs, fix:'2.0.172.43', severity:SECURITY_HOLE);
