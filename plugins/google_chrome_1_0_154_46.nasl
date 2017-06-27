#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35558);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/11/13 21:35:39 $");

  script_cve_id(
    "CVE-2007-0045",
    "CVE-2007-0048",
    "CVE-2009-0276",
    "CVE-2009-0411"
  );
  script_bugtraq_id(21858, 33529, 33773);
  script_osvdb_id(31046, 31596, 52641, 54156);

  script_name(english:"Google Chrome < 1.0.154.46 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.46.  Such versions are reportedly affected by several
issues :

  - Cross-site scripting vulnerabilities in the Adobe Reader
    Plugin itself could be leveraged using a PDF document to
    run scripts on arbitrary sites via Google Chrome.
    (CVE-2007-0048 and CVE-2007-0045)

  - A cross-domain security-bypass vulnerability that could
    allow an attacker to bypass the same-origin policy and
    gain access to potentially sensitive information.
    (CVE-2009-0276)

  - A remote attacker may be able to gain access to the
    'Set-Cookie' and 'Set-Cookie2' response headers via
    XMLHttpRequest calls. (CVE-2009-0411)");
  # http://googlechromereleases.blogspot.com/2009/01/stable-beta-update-yahoo-mail-and.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e94a6f2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome version 1.0.154.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");
  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'1.0.154.46', xss:TRUE, severity:SECURITY_WARNING);
