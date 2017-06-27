#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47781);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id(
    "CVE-2010-0654",
    "CVE-2010-1205",
    "CVE-2010-1208",
    "CVE-2010-1209",
    "CVE-2010-1211",
    "CVE-2010-1212",
    "CVE-2010-1213",
    "CVE-2010-1214",
    "CVE-2010-2751",
    "CVE-2010-2752",
    "CVE-2010-2753",
    "CVE-2010-2754"
  );
  script_bugtraq_id(
    41842,
    41845,
    41849,
    41852,
    41853,
    41859,
    41860,
    41871,
    41872,
    41968
  );
  script_osvdb_id(
    62464,
    65852,
    66590,
    66592,
    66593,
    66594,
    66595,
    66596,
    66599,
    66600,
    66601,
    66602,
    66604,
    66605
  );
  script_xref(name:"Secunia", value:"39925");
  script_xref(name:"Secunia", value:"40283");

  script_name(english:"Firefox < 3.5.11 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 3.5.11.  Such
versions are potentially affected by the following security issues :

  - Multiple memory safety bugs could result in memory
    corruption, potentially resulting in arbitrary code
    execution. (MFSA 2010-34)

  - An error in DOM attribute cloning could result in
    arbitrary code execution. (MFSA 2010-35)

  - An error in Mozilla's 'NodeIterator' implementation
    could lead to arbitrary code execution. (MFSA 2010-36)

  - An error in the code to store the names and values of
    plugin parameters could lead arbitrary code execution.
    (MFSA 2010-37)

  - The array class used to store CSS values is affected
    by an integer overflow vulnerability. (MFSA 2010-39)

  - An integer overflow vulnerability exists in the
    'selection' attribute of XUL <tree> element.
    (MFSA 2010-40)

  - A buffer overflow vulnerability in Mozilla graphics
    code could lead to arbitrary code execution.
    (MFSA 2010-41)

  - It is possible to read and parse resources from other
    domains even when the content is not valid JavaScript
    leading to cross-domain data disclosure. (MFSA 2010-42)

  - Multiple location bar spoofing vulnerabilities exist.
    (MFSA 2010-45)

  - It is possible to read data across domains by
    injecting bogus CSS selectors into a target site.
    (MFSA 2010-46)

  - Potentially sensitive URL parameters could be leaked
    across domains via script errors. (MFSA 2010-47)");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-34.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-35.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-36.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-37.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-39.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-40.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-41.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-42.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-45.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-46.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-47.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.5.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/23"); # (MFSA 2010-46)
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/22");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.5.11', severity:SECURITY_HOLE);
