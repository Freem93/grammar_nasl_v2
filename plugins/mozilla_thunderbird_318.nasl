#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52532);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2010-1585", "CVE-2011-0053", "CVE-2011-0061", 
    "CVE-2011-0062");
  script_bugtraq_id(46368, 46645, 46647, 46651);
  script_osvdb_id(
    64150,
    72437,
    72438,
    72439,
    72440,
    72441,
    72442,
    72443,
    72444,
    72445,
    72446,
    72447,
    72448,
    72449,
    72454,
    72465,
    72466
  );
  script_xref(name:"Secunia", value:"43586");

  script_name(english:"Mozilla Thunderbird 3.1 < 3.1.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by 
multiple vulnerabilities.");
  
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.8.
Such versions are potentially affected by multiple vulnerabilities :

  - Multiple memory corruption errors exist and may lead to
    arbitrary code execution. (MFSA 2011-01)

  - An input validation error exists in the class, 
    'ParanoidFragmentSink', which allows inline JavaScript
    and 'javascript:' URLs in a chrome document. Note that
    no unsafe usage occurs in Mozilla products, however
    community generated extensions could.(MFSA 2011-08)

  - A buffer overflow exists related to JPEG decoding and
    may lead to arbitrary code execution. (MFSA 2011-09)");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Apr/202");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-08.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-09.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54e90acb");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.8', min:'3.1.0', severity:SECURITY_HOLE);