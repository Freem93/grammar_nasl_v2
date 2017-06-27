#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22369);
  script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2006-4253",
    "CVE-2006-4340",
    "CVE-2006-4565",
    "CVE-2006-4566",
    "CVE-2006-4567",
    "CVE-2006-4568",
    "CVE-2006-4569",
    "CVE-2006-4571"
  );
  script_bugtraq_id(19488, 19534, 20042);
  script_osvdb_id(
    27974,
    27975,
    28843,
    28844,
    28845,
    28846,
    28847,
    28848,
    29013,
    94476,
    94477,
    94478,
    94479,
    94480,
    95338,
    95339,
    95340,
    95341,
    95911,
    95912,
    95913,
    95914,
    95915,
    96645
  );

  script_name(english:"Firefox < 1.5.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, some of which may lead to execution of arbitrary code on the
affected host subject to the user's privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-57.html");
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-58.html");
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-59.html");
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-60.html");
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-61.html");
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-62.html");
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-64.html");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 79, 119, 264);

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/16");
 script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/09/14");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.5.0.7', severity:SECURITY_HOLE);
