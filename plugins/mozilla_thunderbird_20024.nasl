#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45110);
  script_version("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2009-0689",
    "CVE-2009-2463",
    "CVE-2009-3072",
    "CVE-2009-3075",
    "CVE-2009-3077",
    "CVE-2009-3376",
    "CVE-2010-0161",
    "CVE-2010-0163"
  );
  script_bugtraq_id(37366,38831);
  script_osvdb_id(
    55603,
    56230,
    57972,
    57976,
    57978,
    59389,
    61091,
    63262,
    63263
  );
  script_xref(name:"Secunia", value:"37682");

  script_name(english:"Mozilla Thunderbird < 2.0.0.24 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The installed version of Thunderbird is earlier than 2.0.0.24.  Such
versions are potentially affected by multiple vulnerabilities :

  - The columns of a XUL tree element can be manipulated in
    a particular way that would leave a pointer owned by
    the column pointing to freed memory. (MFSA 2009-49)

  - A heap-based buffer overflow exists in Mozilla's string
    to floating point number conversion routines. 
    (MFSA 2009-59)

  - It is possible to obfuscate the name of files to be
    downloaded by using a right-to-left override character
    (RTL). (MFSA 2009-62)

  - Multiple memory corruption vulnerabilities exist that
    may result in the execution of arbitrary code. 
    (MFSA 2010-07)");

  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-07.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2009/mfsa2009-62.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2009/mfsa2009-59.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2009/mfsa2009-49.html");
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?fff60c73");
  script_set_attribute(attribute:"solution",value:"Upgrade to Thunderbird 2.0.0.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 94, 119, 189);
  script_set_attribute(attribute:"vuln_publication_date",value:"2009/09/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/19");
 script_cvs_date("$Date: 2016/12/05 14:32:01 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.24', severity:SECURITY_HOLE);