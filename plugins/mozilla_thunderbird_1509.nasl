#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(23929);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500",
                "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504",
                "CVE-2006-6505");
  script_bugtraq_id(21668);
  script_osvdb_id(
    31341,
    31342,
    31343,
    31344,
    31345,
    31346,
    31347,
    31348,
    31349,
    31350
  );

  script_name(english:"Mozilla Thunderbird < 1.5.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Mozilla Thunderbird");
 
  script_set_attribute(  attribute:"synopsis",  value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(  attribute:"description",   value:
"The remote version of Mozilla Thunderbird suffers from various
security issues, at least one of which could lead to execution of
arbitrary code on the affected host."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-69.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-70.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-71.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-72.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-73.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-74.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 1.5.0.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/19");
 script_cvs_date("$Date: 2016/05/16 14:12:51 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/11/08");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'1.5.0.9', severity:SECURITY_HOLE);