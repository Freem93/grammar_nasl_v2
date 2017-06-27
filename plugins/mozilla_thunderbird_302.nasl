#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44961);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/09/24 14:12:00 $");

  script_cve_id(
    "CVE-2009-1571",
    "CVE-2010-0159", 
    "CVE-2010-0165",
    "CVE-2010-0167",
    "CVE-2010-0169",
    "CVE-2010-0171"
  );
  script_bugtraq_id(38286, 38287, 38922, 38939, 38946);
  script_osvdb_id(
    62418,
    62419,
    62420,
    62421,
    62422,
    62423,
    62424,
    62425,
    63265,
    63267,
    63268,
    63270,
    63272
  );
  script_xref(name:"Secunia", value:"38657");

  script_name(english:"Mozilla Thunderbird < 3.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 3.0.2.  Such
versions are potentially affected by the following security issues :

  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-01)

  - The HTML parser incorrectly frees used memory when 
    insufficient space is available to process remaining
    input. (MFSA 2010-03)

  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-11)

  - A cross-site scripting issue when using 
    'addEventListener' and 'setTimeout' on a wrapped object.
    (MFSA 2010-12)

  - It is possible to corrupt a user's XUL cache.
    (MFSA 2010-14)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.mozillamessaging.com/en-US/thunderbird/3.0.2/releasenotes" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-01.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-03.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-11.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-12.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-14.html" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Mozilla Thunderbird 3.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);
 
  script_set_attribute(attribute:"vuln_publication_date",   value:"2010/01/20");
  script_set_attribute(attribute:"patch_publication_date",  value:"2010/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.0.2', severity:SECURITY_HOLE);