#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82040);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/05 04:38:20 $");

  script_cve_id("CVE-2015-0817");
  script_bugtraq_id(73263);
  script_osvdb_id(119794);

  script_name(english:"Firefox < 36.0.3 JIT Code Execution");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 36.0.3. It is, therefore, affected by a remote code execution
vulnerability due to an out-of-bounds error in typed array bounds
checking within 'asmjs/AsmJSValidate.cpp', which relates to
just-in-time compilation for JavaScript. A remote attacker, using a
specially crafted web page, can exploit this to execute arbitrary code
by reading and writing to memory.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 36.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'36.0.3', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
