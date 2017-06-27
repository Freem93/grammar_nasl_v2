#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65801);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:43:13 $");

  script_cve_id(
    "CVE-2013-0788",
    "CVE-2013-0791",
    "CVE-2013-0793",
    "CVE-2013-0795",
    "CVE-2013-0800"
  );
  script_bugtraq_id(58819, 58825, 58826, 58836, 58837);
  script_osvdb_id(91874, 91885, 91882, 91880, 91886);

  script_name(english:"Firefox ESR 17.x < 17.0.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox ESR 17.x is earlier than 17.0.5 and
is, therefore, potentially affected by the following vulnerabilities :

  - Various memory safety issues exist. (CVE-2013-0788)

  - An out-of-bounds memory read error exists related to
    'CERT_DecodeCertPackage' and certificate decoding.
    (CVE-2013-0791)

  - An error exists related to navigation, history and
    improper 'baseURI' property values that could allow
    cross-site scripting attacks. (CVE-2013-0793)

  - A error exists related to 'cloneNode' that can allow
    'System Only Wrapper' (SOW) to be bypassed, thus
    violating the same origin policy and possibly leading
    to privilege escalation and code execution.
    (CVE-2013-0795)

  - An out-of-bounds write error exists related to the
    Cairo graphics library. (CVE-2013-0800)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-31/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-36/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-38/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-40/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 17.0.5 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (isnull(get_kb_item(kb_base + '/is_esr'))) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'17.0.5', min:'17.0', severity:SECURITY_HOLE);
