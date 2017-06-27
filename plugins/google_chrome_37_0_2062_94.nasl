#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77409);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/29 20:31:25 $");

  script_cve_id(
    "CVE-2014-3168",
    "CVE-2014-3169",
    "CVE-2014-3170",
    "CVE-2014-3171",
    "CVE-2014-3172",
    "CVE-2014-3173",
    "CVE-2014-3174",
    "CVE-2014-3175",
    "CVE-2014-3176",
    "CVE-2014-3177"
  );
  script_bugtraq_id(
    69398,
    69400,
    69401,
    69402,
    69403,
    69404,
    69405,
    69406,
    69407
  );
  script_osvdb_id(
    110447,
    110448,
    110449,
    110450,
    110451,
    110452,
    110453,
    110454,
    110455
  );

  script_name(english:"Google Chrome < 37.0.2062.94 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 37.0.2062.94. It is, therefore, affected by the following
vulnerabilities :

  - Blink contains a use-after-free vulnerability in its SVG
    implementation. By using a specially crafted web page, a
    remote attacker can cause a denial of service or execute
    arbitrary code. (CVE-2014-3168)

  - Blink contains a use-after-free vulnerability in its DOM
    implementation. By using a specially crafted web page, a
    remote attacker can cause a denial of service or execute
    arbitrary code. (CVE-2014-3169)

  - A flaw exists in the 'url_pattern.cc' file that does not
    prevent the use of NULL characters '\0' in a host name.
    A remote attacker can use this to spoof the extension
    permission dialogue by relying on truncation after this
    character. (CVE-2014-3170)

  - Blink contains a use-after-free vulnerability in its V8
    bindings. By using improper HashMap add operations, a
    remote attacker can cause a denial of service or execute
    arbitrary code. (CVE-2014-3171)

  - The Debugger extension API does not properly a validate
    a tab's URL before attaching. A remote attacker can
    therefore bypass access limitations by means of an
    extension that uses a restricted URL. (CVE-2014-3172)

  - A flaw exists in the WebGL implementation where clear
    calls do not interact properly with the draw buffer. By
    using a specially crafted CANVAS element, a remote
    attacker can cause a denial of service. (CVE-2014-3173)

  - A flaw exists in the Blink Web Audio API implementation
    in how it updates biquad filter coefficients when there
    are concurrent threads. By using specially crafted API
    calls, a remote attacker can cause a denial of service.
    (CVE-2014-3174)

  - Flaws exist in the 'load_truetype_glyph' function and
    other unspecified functions which can be exploited by a
    remote attacker to cause a denial of service or other
    impact. (CVE-2014-3175)

  - Flaws exist related to the interaction of the IPC, Sync
    API, and V8 extensions. A remote attacker can exploit
    these to bypass the sandbox and execute arbitrary code.
    (CVE-2014-3176, CVE-2014-3177)");
  # http://googlechromereleases.blogspot.com/2014/08/stable-channel-update_26.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc0adbf3");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 37.0.2062.94 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'37.0.2062.94', severity:SECURITY_HOLE, xss:FALSE);
