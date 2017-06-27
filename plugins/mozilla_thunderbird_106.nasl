#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(19269);
 script_version("$Revision: 1.27 $");
 script_cve_id(
   "CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", 
   "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", 
   "CVE-2005-2269", "CVE-2005-2270"
 );
 script_bugtraq_id(12988, 13233, 13645, 14242);
 script_osvdb_id(
   7296,
   15241,
   15682,
   15689,
   15690,
   16605,
   17913,
   17942,
   17964,
   17968,
   17969,
   17970
 );
 script_xref(name:"Secunia", value:"16062");

 script_name(english:"Mozilla Thunderbird < 1.0.6 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Mozilla Thunderbird");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The installed version of Mozilla Thunderbird is affected by
multiple vulnerabilities, at least one of which could allow a remote
attacker to execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/known-vulnerabilities/thunderbird10.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-33.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-40.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-41.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-44.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-46.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-50.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-52.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-55.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-56.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla Thunderbird 1.0.6 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/30");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/07/19");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Thunderbird/Version");
 exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'1.0.6', severity:SECURITY_HOLE);