#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76760);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id(
    "CVE-2014-1544",
    "CVE-2014-1547",
    "CVE-2014-1548",
    "CVE-2014-1555",
    "CVE-2014-1557"
  );
  script_bugtraq_id(
    68811,
    68814,
    68816,
    68818,
    68822,
    68824
  );
  script_osvdb_id(
    109409,
    109410,
    109411,
    109412,
    109413,
    109414,
    109415,
    109416,
    109417,
    109418,
    109419,
    109420,
    109421,
    109422,
    109423,
    109424,
    109425,
    109426,
    109427,
    109428,
    109429,
    109430,
    109431,
    109432,
    109433,
    109434,
    109438,
    109439
  );

  script_name(english:"Mozilla Thunderbird 24.x < 24.7 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird 24.x installed on the remote host is a version
prior to 24.7. It is, therefore, affected by the following
vulnerabilities :

  - When a pair of NSSCertificate structures are added to a
    trust domain and then one of them is removed during use,
    a use-after-free error occurs which may cause the
    application to crash. This crash is potentially
    exploitable. (CVE-2014-1544)

  - There are multiple memory safety hazards within the
    browser engine. These hazards may lead to memory
    corruption vulnerabilities, which may allow attackers
    to execute arbitrary code. (CVE-2014-1547,
    CVE-2014-1548)

  - Triggering the FireOnStateChange event has the
    potential to crash the application. This may lead to
    a use-after-free and an exploitable crash.
    (CVE-2014-1555)

  - When using the Cesium JavaScript library to generate
    WebGL content, the application may crash. This crash
    is potentially exploitable. (CVE-2014-1556)

  - There is a flaw in the Skia library when scaling images
    of high quality. If the image data is discarded while
    being processed, the library may crash. This crash
    is potentially exploitable. (CVE-2014-1557)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-56.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-61.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-62.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-63.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-64.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 24.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Thunderbird install is in the ESR branch.');

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'24.7', min:'24.0', severity:SECURITY_HOLE, xss:FALSE);
