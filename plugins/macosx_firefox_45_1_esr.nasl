#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90789);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/06 13:21:20 $");

  script_cve_id(
    "CVE-2016-2806",
    "CVE-2016-2807",
    "CVE-2016-2808",
    "CVE-2016-2814"
  );
  script_bugtraq_id(88099, 88100);
  script_osvdb_id(
    137609,
    137610,
    137613,
    137614,
    137615,
    137616,
    137617,
    137618,
    137619,
    137620,
    137621,
    137622,
    137623,
    137624,
    137625,
    137626,
    137627,
    137628,
    137639,
    137642
  );
  script_xref(name:"MFSA", value:"2016-39");
  script_xref(name:"MFSA", value:"2016-44");
  script_xref(name:"MFSA", value:"2016-47");

  script_name(english:"Firefox ESR 45.x < 45.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Mac OS X host is
45.x prior to 45.1. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    attacker to corrupt memory, resulting in the execution
    of arbitrary code. (CVE-2016-2806, CVE-2016-2807)

  - A flaw exists due to improper validation of
    user-supplied input when handling the 32-bit generation
    count of the underlying HashMap. A context-dependent
    attacker can exploit this to cause a buffer overflow
    condition, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2016-2808)

  - A heap buffer overflow condition exists in the Google
    Stagefright component due to improper validation of
    user-supplied input when handling CENC offsets and the
    sizes table. A context-dependent attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-2814)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-44/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-47/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR version 45.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'45.1', min:'45.0', severity:SECURITY_HOLE);
