#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99137);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id(
    "CVE-2017-5052",
    "CVE-2017-5053",
    "CVE-2017-5054",
    "CVE-2017-5055",
    "CVE-2017-5056"
  );
  script_bugtraq_id(
    97220,
    97221
  );
  script_osvdb_id(
    154634,
    154635,
    154636,
    154637,
    154638
  );

  script_name(english:"Google Chrome < 57.0.2987.133 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 57.0.2987.133. It is, therefore, affected by the
following vulnerabilities :

  - A type cast error exists in Blink in the
    LayoutInline::absoluteVisualRect() function within file
    layout/LayoutInline.cpp that allows an unauthenticated,
    remote attacker to cause an unspecified impact.
    (CVE-2017-5052)

  - An out-of-bounds read error exists in V8 in the
    IndexOfValueImpl() function template within file
    builtins/builtins-array.cc when handling arrays. An
    unauthenticated, remote attacker can exploit this to
    disclose memory content. (CVE-2017-5053)

  - A heap buffer overflow condition exists in V8 that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-5054)

  - A use-after-free error exists in the PrintViewManager
    class within file printing/print_view_manager.cc when
    handling previews. An unauthenticated, remote attacker
    can exploit this to deference already freed memory,
    resulting in the execution arbitrary code.
    (CVE-2017-5055)

  - A use-after-free error exists in the Blink that allows
    an unauthenticated, remote attacker to dereference
    already freed memory, resulting in the execution of
    arbitrary code. (CVE-2017-5056)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/03/stable-channel-update-for-desktop_29.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?64842ac1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 57.0.2987.133 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'57.0.2987.133', severity:SECURITY_HOLE);
