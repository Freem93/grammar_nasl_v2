#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74441);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/26 00:30:55 $");

  script_cve_id(
    "CVE-2014-1533",
    "CVE-2014-1534",
    "CVE-2014-1536",
    "CVE-2014-1537",
    "CVE-2014-1538",
    "CVE-2014-1541"
  );
  script_bugtraq_id(67964, 67965, 67966, 67971, 67976, 67979);

  script_name(english:"Mozilla Thunderbird < 24.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote host is a version
prior to 24.6 and is, therefore, affected by the following
vulnerabilities :

  - Memory issues exist that could lead to arbitrary code
    execution. (CVE-2014-1533, CVE-2014-1534)

  - An out-of-bounds read issue exists in
    'PropertyProvider::FindJustificationRange'.
    (CVE-2014-1536)

  - Use-after-free memory issues exist in
    'mozilla::dom::workers::WorkerPrivateParent',
    'nsTextEditRules::CreateMozBR', and the SMIL Animation
    Controller that could lead to code execution.
    (CVE-2014-1537, CVE-2014-1538, CVE-2014-1541)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-48.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-49.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-52.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 24.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'24.6', severity:SECURITY_HOLE, xss:FALSE);
