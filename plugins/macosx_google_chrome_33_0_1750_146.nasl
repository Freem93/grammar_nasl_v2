#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72801);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id(
    "CVE-2013-6663",
    "CVE-2013-6664",
    "CVE-2013-6665",
    "CVE-2013-6666",
    "CVE-2013-6667",
    "CVE-2013-6668"
  );
  script_bugtraq_id(65930);
  script_osvdb_id(
    103938,
    103939,
    103940,
    103941,
    103942,
    103943,
    103944,
    103945,
    103946,
    103947,
    103948,
    103949,
    103950,
    103951,
    103952,
    103953,
    103984,
    104059,
    104068
  );

  script_name(english:"Google Chrome < 33.0.1750.146 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 33.0.1750.146.  It is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to handling
    SVG images and speech recognition processing.
    (CVE-2013-6663, CVE-2013-6664)

  - An error exists related to software rendering that
    could allow heap-based buffer overflows.
    (CVE-2013-6665)

  - An error exists related to Flash header requests.
    (CVE-2013-6666)

  - Various unspecified errors exist having unspecified
    impacts. (CVE-2013-6667)

  - Unspecified errors exist related to the V8 JavaScript
    engine that could have unspecified impacts.
    (CVE-2013-6668)");
  # http://googlechromereleases.blogspot.com/2014/03/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?246aa148");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 33.0.1750.146 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'33.0.1750.146', severity:SECURITY_WARNING);
