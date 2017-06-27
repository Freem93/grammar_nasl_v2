#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90791);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/06 13:21:20 $");

  script_cve_id(
    "CVE-2016-2805",
    "CVE-2016-2807",
    "CVE-2016-2808",
    "CVE-2016-2814"
  );
  script_bugtraq_id(88099, 88100);
  script_osvdb_id(
    135562,
    137609,
    137613,
    137614,
    137615,
    137616,
    137639,
    137642
  );
  script_xref(name:"MFSA", value:"2016-39");
  script_xref(name:"MFSA", value:"2016-44");
  script_xref(name:"MFSA", value:"2016-47");

  script_name(english:"Firefox ESR < 38.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
prior to 38.8. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    attacker to corrupt memory, resulting in the execution
    of arbitrary code. (CVE-2016-2805, CVE-2016-2807)

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
"Upgrade to Firefox ESR version 38.8 or later.");
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
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'38.8', severity:SECURITY_HOLE);
