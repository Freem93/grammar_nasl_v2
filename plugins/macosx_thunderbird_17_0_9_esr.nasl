#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69990);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/06 11:54:17 $");

  script_cve_id(
    "CVE-2013-1718",
    "CVE-2013-1719",
    "CVE-2013-1725",
    "CVE-2013-1730",
    "CVE-2013-1732",
    "CVE-2013-1735",
    "CVE-2013-1736",
    "CVE-2013-1737"
  );
  script_bugtraq_id(
    62462,
    62463,
    62467,
    62469,
    62473,
    62475,
    62478,
    62479
  );
  script_osvdb_id(
    97388,
    97389,
    97390,
    97391,
    97392,
    97398,
    97403,
    97404
  );

  script_name(english:"Thunderbird ESR 17.x < 17.0.9 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a mail client that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird ESR 17.x is prior to 17.0.9 and
is, therefore, potentially affected the following vulnerabilities :

  - Memory issues exist in the browser engine that could
    allow for denial of service or arbitrary code execution.
    (CVE-2013-1718, CVE-2013-1719)

  - Multiple use-after-free problems exist that could result
    in denial of service attacks or arbitrary code
    execution. (CVE-2013-1735, CVE-2013-1736)

  - A buffer overflow is possible because of an issue with
    multi-column layouts. (CVE-2013-1732)

  - A JavaScript compartment mismatch could result in a
    denial of service or arbitrary code execution. Versions
    of Firefox 20 or greater are not susceptible to the
    arbitrary code execution mentioned above.
    (CVE-2013-1730)

  - Incorrect scope handling for JavaScript objects with
    compartments could result in denial of service or
    possibly arbitrary code execution. (CVE-2013-1725)

  - An object is not properly identified during use of
    user-defined getter methods on DOM proxies. This could
    result in access restrictions being bypassed.
    (CVE-2013-1737)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-76.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-82.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-88.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-89.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-90.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-91.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird ESR 17.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}


include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Thunderbird ESR");

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:TRUE, fix:'17.0.9', min:'17.0', severity:SECURITY_HOLE, xss:FALSE);
