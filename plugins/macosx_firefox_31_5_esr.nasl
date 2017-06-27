#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81517);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2015-0822",
    "CVE-2015-0827",
    "CVE-2015-0831",
    "CVE-2015-0835",
    "CVE-2015-0836"
  );
  script_bugtraq_id(
    72742,
    72746,
    72748,
    72755,
    72756
  );
  script_osvdb_id(
    118696,
    118699,
    118704,
    118707,
    118709,
    118710,
    118711,
    118712,
    118713,
    118714,
    118715,
    118716,
    118717,
    118718,
    118719,
    118720,
    118721,
    118722,
    118723,
    118724,
    118725,
    118726,
    118727
  );

  script_name(english:"Firefox ESR 31.x < 31.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR 31.x installed on the remote Mac OS X host
is prior to 31.5. It is, therefore, affected by the following
vulnerabilities :

  - An information disclosure vulnerability exists related
    to the autocomplete feature that allows an attacker to
    read arbitrary files. (CVE-2015-0822)

  - An out-of-bounds read and write issue exists when
    processing invalid SVG graphic files. This allows an
    attacker to disclose sensitive information.
    (CVE-2015-0827)

  - A use-after-free issue exists when running specific web
    content with 'IndexedDB' to create an index, resulting
    in a denial of service condition or arbitrary code
    execution. (CVE-2015-0831)

  - Multiple unspecified memory safety issues exist within
    the browser engine. (CVE-2015-0835, CVE-2015-0836)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-16/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-19/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-24/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox ESR 31.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'31.5', min:'31.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
