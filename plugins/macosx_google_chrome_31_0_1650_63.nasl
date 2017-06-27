#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71228);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id(
    "CVE-2013-6634",
    "CVE-2013-6635",
    "CVE-2013-6636",
    "CVE-2013-6637",
    "CVE-2013-6638",
    "CVE-2013-6639",
    "CVE-2013-6640"
  );
  script_bugtraq_id(64078);
  script_osvdb_id(
    100583,
    100584,
    100585,
    100586,
    100587,
    100588,
    100589,
    100590,
    100591,
    100592,
    100593,
    100594,
    100595,
    100596

  );

  script_name(english:"Google Chrome < 31.0.1650.63 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 31.0.1650.63.  It is, therefore, affected by the
following vulnerabilities :

  - An error exists related to session fixation, the sync
    process and HTTP 302 redirects. (CVE-2013-6634)

  - A use-after-free error exists related to the editing
    process. (CVE-2013-6635)

  - An error exists related to modal dialogs that could
    allow address spoofing. (CVE-2013-6636)

  - Various unspecified errors exist having unspecified
    impacts. (CVE-2013-6637)

  - An out-of-bounds read error, an out-of-bounds write
    error and a buffer overflow error exist in the v8
    JavaScript engine. (CVE-2013-6638, CVE-2013-6639,
    CVE-2013-6640)");
  # http://googlechromereleases.blogspot.com/2013/12/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc90df4b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 31.0.1650.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'31.0.1650.63', severity:SECURITY_WARNING);
