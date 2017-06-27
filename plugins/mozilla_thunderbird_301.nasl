#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(44111);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2009-3979","CVE-2009-3980",
                "CVE-2009-3981","CVE-2009-3982",
                "CVE-2009-3388","CVE-2009-3389");
  script_bugtraq_id(37361, 37362, 37363, 37364);
  script_osvdb_id(61093, 61094, 61096, 61097, 61098, 61102, 61103);
  script_xref(name:"Secunia", value:"37783");

  script_name(english:"Mozilla Thunderbird < 3.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 3.0.1.  Such
versions are potentially affected by the following security issues :

  - Multiple crashes can result in arbitrary code
    execution. (MFSA 2009-65)
  
  - Multiple vulnerabilities in 'liboggplay' can lead to
    arbitrary code execution. (MFSA 2009-66)
  
  - An integer overflow in the 'Theora' video library can
    lead to a crash or the execution of arbitrary code.
    (MFSA 2009-67)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozillamessaging.com/en-US/thunderbird/3.0.1/releasenotes" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-65.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-66.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-67.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird 3.0.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);
 
  script_set_attribute(attribute:"vuln_publication_date",   value:"2010/01/20");
  script_set_attribute(attribute:"patch_publication_date",  value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/22");

 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.0.1', severity:SECURITY_HOLE);