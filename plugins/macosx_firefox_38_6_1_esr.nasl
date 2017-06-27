#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88751);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/03 14:10:43 $");

  script_cve_id("CVE-2016-1523", "CVE-2016-1969");
  script_bugtraq_id(82991);
  script_osvdb_id(134246, 135666);
  script_xref(name:"MFSA", value:"2016-14");
  script_xref(name:"MFSA", value:"2016-38");

  script_name(english:"Firefox ESR < 38.6.1 Multiple Graphite 2 Library RCE (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Mac OS X
host is prior to 38.6.1. It is, therefore, affected by multiple remote
code execution vulnerabilities in the Graphite 2 library :

  - An overflow condition exists in the Context Item
    functionality due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a crafted Graphite smart font, to
    cause a heap-based buffer overflow, resulting in a
    denial of service or the execution of arbitrary code.
    (CVE-2016-1523)

  - An out-of-bounds write error exists in the setAttr()
    function that is triggered when handling maliciously
    crafted fonts. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-1969");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-14/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-38/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 38.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'38.6.1', severity:SECURITY_HOLE);
