#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21628);
  script_version("$Revision: 1.20 $");

  script_cve_id(
    "CVE-2006-2775", 
    "CVE-2006-2776", 
    "CVE-2006-2778", 
    "CVE-2006-2779", 
    "CVE-2006-2780", 
    "CVE-2006-2781", 
    "CVE-2006-2783", 
    "CVE-2006-2786", 
    "CVE-2006-2787"
  );
  script_bugtraq_id(18228);
  script_osvdb_id(
    26298,
    26300,
    26301,
    26302,
    26303,
    26304,
    26305,
    26306,
    26307,
    26308,
    26310,
    26311,
    26312,
    26314
  );

  script_name(english:"Mozilla Thunderbird < 1.5.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Mozilla Thunderbird");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Mozilla Thunderbird suffers from various 
security issues, some of which could lead to execution of arbitrary 
code on the affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-32.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-33.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-35.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-40.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-42.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird 1.5.0.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94, 119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/06/01");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'1.5.0.4', severity:SECURITY_HOLE);