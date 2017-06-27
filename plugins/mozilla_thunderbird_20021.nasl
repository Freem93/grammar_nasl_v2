#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35977);
  script_version("$Revision: 1.18 $");

  script_cve_id(
    "CVE-2009-0040",
    "CVE-2009-0352",
    "CVE-2009-0353",
    "CVE-2009-0652",
    "CVE-2009-0771",
    "CVE-2009-0772",
    "CVE-2009-0773",
    "CVE-2009-0774",
    "CVE-2009-0776"
  );
  script_bugtraq_id(33598, 33827, 33837, 33990);
    script_osvdb_id(
      51929,
      51931,
      51932,
      51933,
      51934,
      51935,
      51936,
      51937,
      51938,
      51939,
      51940,
      52444,
      52445,
      52446,
      52447,
      52448,
      52449,
      52451,
      52659,
      53315,
      53316,
      53317
    );
  if (NASL_LEVEL >= 3000)
  {
  }

  script_name(english:"Mozilla Thunderbird < 2.0.0.21 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 2.0.0.21.  Such
versions are potentially affected by the following security issues :

  - There are several stability bugs in the browser engine
    that could lead to crashes with evidence of memory
    corruption. (MFSA 2009-01)

  - By exploiting stability bugs in the browser engine, it 
    might be possible for an attacker to execute arbitrary 
    code on the remote system under certain conditions. 
    (MFSA 2009-07)

  - It might be possible for a website to read arbitrary XML
    data from another domain by using nsIRDFService and a 
    cross-domain redirect. (MFSA 2009-09)

  - Vulnerabilities in the PNG libraries used by Mozilla
    could be exploited to execute arbitrary code on the 
    remote system. (MFSA 2009-10)

  - A URI-spoofing vulnerability exists because the 
    application fails to adequately handle specific 
    characters in IDN subdomains. (MFSA 2009-15)"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-07.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-09.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-15.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.com/en-US/thunderbird/2.0.0.21/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.21 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 200, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/20");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/02/03");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.21', severity:SECURITY_HOLE);