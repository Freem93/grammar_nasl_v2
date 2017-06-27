#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(28226);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-4841", "CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(26132);
  script_osvdb_id(38030, 38043, 38044);

  script_name(english:"Mozilla Thunderbird < 2.0.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Mozilla Thunderbird");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The remote version of Mozilla Thunderbird is affected by some memory
corruption issues that could result in remote code execution if
JavaScript is enabled when viewing specially crafted messages."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-36.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/10/18");
 script_cvs_date("$Date: 2016/05/16 14:12:51 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.9', min:'2.0', severity:SECURITY_HOLE);