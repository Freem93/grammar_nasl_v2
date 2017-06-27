#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(32134);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235",
                "CVE-2008-1236", "CVE-2008-1237");
  script_osvdb_id(
    43857,
    43858,
    43859,
    43860,
    43861,
    43862,
    43863,
    43864,
    43865,
    43866,
    43867,
    43868,
    43869,
    43870,
    43871,
    43872,
    43873,
    43874,
    43875,
    43876,
    43877,
    43878
  );

  script_name(english:"Mozilla Thunderbird < 2.0.0.14 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is affected by various security
issues :

  - A series of vulnerabilities exist that allow for
    JavaScript privilege escalation and arbitrary code
    execution.

  - Several stability bugs exist leading to crashes which,
    in some cases, show traces of memory corruption.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-15.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Mozilla Thunderbird 2.0.0.14 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 94, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/03/25");

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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.14', severity:SECURITY_HOLE);
