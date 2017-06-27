#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85744);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id(
    "CVE-2015-1291",
    "CVE-2015-1292",
    "CVE-2015-1293",
    "CVE-2015-1294",
    "CVE-2015-1295",
    "CVE-2015-1296",
    "CVE-2015-1297",
    "CVE-2015-1298",
    "CVE-2015-1299",
    "CVE-2015-1300",
    "CVE-2015-1301"
  );
  script_osvdb_id(
    126935,
    126936,
    126937,
    126938,
    126939,
    126940,
    126941,
    126942,
    126943,
    126944,
    126945,
    126946
  );

  script_name(english:"Google Chrome < 45.0.2454.85 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 45.0.2454.85. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-origin bypass vulnerability exists due to a flaw
    in the ContainerNode::parserRemoveChild() function in 
    ContainerNode.cpp wherein user scripts may unexpectedly
    run in 'onunload' handlers during Document Object Model
    (DOM) modification. A remote attacker can exploit this,
    via a specially crafted web page, to bypass cross-origin
    restrictions. (CVE-2015-1291)

  - A cross-origin bypass vulnerability exists due to a flaw
    in the LocalDOMWindow::navigator() function in
    LocalDOMWindow.cpp wherein an incorrect navigator
    associated with a frame may be returned. A remote
    attacker can exploit this, via a specially crafted web
    page, to bypass cross-origin restrictions.
    (CVE-2015-1292)

  - An unspecified cross-origin bypass vulnerability exists
    that allows a remote attacker, via a specially crafted
    web page, to bypass cross-origin restrictions.
    (CVE-2015-1293)

  - A use-after-free error exists in the
    SkMatrix::invertNonIdentity() function in SkMatrix.cpp.
    A remote attacker can exploit this to dereference
    already freed memory, potentially resulting in the
    execution of arbitrary code. (CVE-2015-1294)

  - A use-after-free error exists in
    print_web_view_helper.cc that is triggered when handling
    nested IPC handlers. A remote attacker can exploit this
    to dereference already freed memory, potentially
    resulting in the execution of arbitrary code.
    (CVE-2015-1295)

  - A spoofing vulnerability exists due to a flaw that is
    triggered when displaying a URL containing certain
    characters in an omnibox. A remote attacker can exploit
    this to include characters that may look like a padlock,
    spoofing a secure connection. (CVE-2015-1296)

  - An unspecified flaw exists related to permission scoping
    as requests in an extension are not hidden from other
    extensions. (CVE-2015-1297)

  - An unspecified URL handling issue exists as the URL to
    be opened after an extension is uninstalled is not
    restricted to HTTP and HTTPS. (CVE-2015-1298)

  - A use-after-free error exists due to improper validation
    of user-supplied input. A remote attacker can exploit
    this to dereference already freed memory, potentially
    resulting in the execution of arbitrary code.
    (CVE-2015-1299)

  - An unspecified information disclosure vulnerability
    exists in Blink. (CVE-2015-1300)

  - Multiple unspecified flaws exist that allow an attacker
    to have unspecified medium severity impact.
    (CVE-2015-1301)");
  # http://googlechromereleases.blogspot.com/2015/09/stable-channel-update.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?96b510c5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 45.0.2454.85 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/02");

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

google_chrome_check_version(fix:'45.0.2454.85', severity:SECURITY_HOLE);
