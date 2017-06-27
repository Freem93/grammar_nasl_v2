#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94959);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id(
    "CVE-2016-5290",
    "CVE-2016-5291",
    "CVE-2016-5293",
    "CVE-2016-5294",
    "CVE-2016-5296",
    "CVE-2016-5297",
    "CVE-2016-9064",
    "CVE-2016-9066",
    "CVE-2016-9074"
  );
  script_bugtraq_id(
    94335,
    94336,
    94339,
    94341
  );
  script_osvdb_id(
    147338,
    147340,
    147341,
    147342,
    147343,
    147345,
    147352,
    147362,
    147375,
    147376,
    147377,
    147378,
    147379,
    147380,
    147381,
    147382,
    147383,
    147384,
    147385,
    147386
  );
  script_xref(name:"MFSA", value:"2016-90");

  script_name(english:"Mozilla Firefox ESR 45.x < 45.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
host is 45.x prior to 45.5. It is, therefore, affected by multiple
vulnerabilities, the majority of which are remote code execution
vulnerabilities. An unauthenticated, remote attacker can exploit these
vulnerabilities by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-90/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 45.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'45.5', min:'45.0', severity:SECURITY_HOLE);
