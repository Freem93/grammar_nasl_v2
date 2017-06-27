#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86381);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:42:41 $");

  script_cve_id(
    "CVE-2015-6755",
    "CVE-2015-6756",
    "CVE-2015-6757",
    "CVE-2015-6758",
    "CVE-2015-6759",
    "CVE-2015-6760",
    "CVE-2015-6761",
    "CVE-2015-6762",
    "CVE-2015-6763"
  );
  script_osvdb_id(
    128813,
    128814,
    128815,
    128816,
    128817,
    128818,
    128819,
    128820,
    128821,
    128828,
    128829,
    128830,
    128831,
    128832,
    128833,
    128834
  );

  script_name(english:"Google Chrome < 46.0.2490.71 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 46.0.2490.71. It is, therefore, affected by multiple
vulnerabilities :

  - A same-origin bypass vulnerability exists in Blink that
    allows an attacker to bypass the same-origin policy.
    (CVE-2015-6755)

  - A use-after-free error exists in PDFium. A remote
    attacker can exploit this to dereference already freed
    memory, potentially resulting in the execution of
    arbitrary code or a denial of service condition.
    (CVE-2015-6756)

  - A use-after-free error exists in ServiceWorker. A remote
    attacker can exploit this to dereference already freed
    memory, potentially resulting in the execution of
    arbitrary code. (CVE-2015-6757)

  - An unspecified bad cast issue exists in PDFium that a
    remote attacker can exploit to have an unspecified
    impact. (CVE-2015-6758)

  - An unspecified flaw exists in LocalStorage that allows
    an attacker to disclose sensitive information.
    (CVE-2015-6759)

  - An unspecified flaw exists when handling errors that
    allows an attacker to have an unspecified impact.
    (CVE-2015-6760)

  - A memory corruption issues exists in FFMpeg due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-6761)

  - An unspecified flaw exists when handling CSS fonts. An
    attacker can exploit this to bypass cross-origin
    resource sharing (CORS) restrictions. (CVE-2015-6762)

  - Multiple unspecified high severity issues exist that
    allow an attacker to have an unspecified impact.
    (CVE-2015-6763)");
  # http://googlechromereleases.blogspot.com/2015/10/stable-channel-update.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?7a25de1b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 46.0.2490.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'46.0.2490.71', severity:SECURITY_HOLE);
