#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(31193);
  script_version("$Revision: 1.21 $");

  script_cve_id(
    "CVE-2008-0304", 
    "CVE-2008-0412", 
    "CVE-2008-0413",
    "CVE-2008-0415", 
    "CVE-2008-0416", 
    "CVE-2008-0418"
  );
  script_bugtraq_id(27406, 27683, 28012, 29303);
  script_osvdb_id(
    41187,
    41220,
    41222,
    41223,
    42056,
    42428,
    43456,
    43457,
    43458,
    43459,
    43460,
    43461,
    43462
  );

  script_name(english:"Mozilla Thunderbird < 2.0.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute( attribute:"synopsis",  value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(  attribute:"description",   value:
"The installed version of Thunderbird is affected by various security
issues :

  - Several stability bugs exist leading to crashes which, in
    some cases, show traces of memory corruption.

  - Several issues exist that allow scripts from page
    content to escape from their sandboxed context and/or
    run with chrome privileges, resulting in privilege
    escalation, cross-site scripting, and/or remote code
    execution.

  - A directory traversal vulnerability exist via the
    'chrome:' URI.

  - A heap-based buffer overflow exists that can be
    triggered when viewing an email with an external MIME
    body.

  - Multiple cross-site scripting vulnerabilities
    exist related to character encoding."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-13.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Mozilla Thunderbird 2.0.0.12 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 119, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/27");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/02/07");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.12', severity:SECURITY_HOLE);
