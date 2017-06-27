#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88753);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/03 14:10:43 $");

  script_cve_id("CVE-2016-1523", "CVE-2016-1969");
  script_bugtraq_id(82991);
  script_osvdb_id(134246, 135666);
  script_xref(name:"MFSA", value:"2016-14");
  script_xref(name:"MFSA", value:"2016-38");

  script_name(english:"Firefox ESR < 38.6.1 Multiple Graphite 2 Library RCE");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
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
    exploit this to execute arbitrary code. (CVE-2016-1969)");
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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'38.6.1', severity:SECURITY_HOLE);
