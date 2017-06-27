#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41000);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2009-3263", "CVE-2009-3264");
  script_bugtraq_id(36416);
  script_osvdb_id(58192, 58193);
  script_xref(name:"Secunia", value:"36770");

  script_name(english:"Google Chrome < 3.0.195.21 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 3.0.195.21.  Such versions are reportedly affected by multiple
issues :

  - Google Chrome's inbuilt RSS/ATOM reader renders
    untrusted JavaScript in an RSS/ATOM feed. Provided a
    victim connects to a RSS/ATOM feed link controlled by
    an attacker or a trusted website allows injecting
    arbitrary JavaScript content into the site's RSS or
    ATOM feed, it may  be possible for an attacker to
    execute arbitrary JavaScript within the victim's browser.
    (Issue #21238)

  - It may be possible to bypass the same origin policy via the
    getSVGDocument() function. (Issue #21338)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ee26e61");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Sep/201");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=21238");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=21338");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 3.0.195.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");

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
google_chrome_check_version(installs:installs, fix:'3.0.195.21', severity:SECURITY_WARNING);
