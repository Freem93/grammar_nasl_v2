#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100300);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/19 21:01:51 $");

  script_cve_id("CVE-2017-6984");
  script_osvdb_id(157545);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-05-15-6");

  script_name(english:"Apple iTunes < 12.6.1 WebKit Memory Corruption RCE (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.6.1. It is, therefore, affected by a remote code execution
vulnerability due to memory corruption caused by improper validation
of user-supplied input. An unauthenticated, remote attacker can
exploit this, by convincing a user to open maliciously crafted web
content, to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207805");
  # https://lists.apple.com/archives/security-announce/2017/May/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61d9f148");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);

constraints = [{"fixed_version" : "12.6.1"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
