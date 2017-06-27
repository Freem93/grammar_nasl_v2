#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90542);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/01 15:11:52 $");

  script_cve_id(
    "CVE-2016-1651",
    "CVE-2016-1652",
    "CVE-2016-1653",
    "CVE-2016-1654",
    "CVE-2016-1655",
    "CVE-2016-1656",
    "CVE-2016-1657",
    "CVE-2016-1658",
    "CVE-2016-1659"
  );
  script_osvdb_id(
    130175,
    131598,
    135124,
    137041,
    137042,
    137044,
    137045,
    137046,
    137047,
    137048,
    137051,
    137052,
    137053,
    137054,
    137055,
    137056,
    137057,
    137058,
    137059,
    137060,
    137061
  );

  script_name(english:"Google Chrome < 50.0.2661.75 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 50.0.2661.75. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists in PDFium in the
    sycc420_to_rgb() and sycc422_to_rgb() functions within
    file fxcodec/codec/fx_codec_jpx_opj.cpp that is
    triggered when decoding JPEG2000 images. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service or disclose memory contents.
    (CVE-2016-1651)

  - A cross-site scripting vulnerability exists due to
    a failure by extension bindings to validate input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a crafted request, to
    execute arbitrary script code in the user's browser
    session. (CVE-2016-1652)

  - An out-of-bounds write error exists in Google V8,
    related to the LoadBuffer operator, that is triggered
    when handling typed arrays. An unauthenticated, remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service or the execution of arbitrary
    code. (CVE-2016-1653)

  - An uninitialized memory read error exists in media
    that allows an attacker to have an unspecified impact.
    No other details are available. (CVE-2016-1654)

  - A use-after-free error exists in extensions that is
    triggered when handling frame removal by content
    scripts. An unauthenticated, remote attacker can exploit
    this to dereference already freed memory, resulting in
    arbitrary code execution. (CVE-2016-1655)

  - A flaw exists, related to content disposition, due to
    the improper sanitization of the names of downloaded
    files. An unauthenticated, remote attacker can exploit
    this to bypass path restrictions. (CVE-2016-1656)

  - A flaw exists in the FocusLocationBarByDefault()
    function of the WebContentsImpl class within the file
    content/browser/web_contents/web_contents_impl.cc that
    allows an authenticated, remote attacker to spoof the
    address bar. (CVE-2016-1657)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to access sensitive
    information by using malicious extensions.
    (CVE-2016-1658)

  - Multiple vulnerabilities exist in Chrome, the most
    serious of which allow an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-1659)");
  # http://googlechromereleases.blogspot.com/2016/04/stable-channel-update_13.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?d2fb8d51");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 50.0.2661.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'50.0.2661.75', severity:SECURITY_HOLE, xss:TRUE);
