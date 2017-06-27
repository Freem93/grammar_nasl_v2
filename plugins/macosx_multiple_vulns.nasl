#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12257);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2013/11/27 17:20:55 $");

 script_cve_id("CVE-2004-0171", "CVE-2004-0430", "CVE-2004-0485", "CVE-2004-0513", "CVE-2004-0514",
               "CVE-2004-0515", "CVE-2004-0516", "CVE-2004-0517", "CVE-2004-0518");
 script_bugtraq_id(10268, 10271, 10432);
 script_osvdb_id(4124, 5762, 6536, 8434, 8435, 8436, 8437, 8438, 8439);

 script_name(english:"Mac OS X < 10.3.4 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is older than
10.3.4.  Such versions contain several flaws that may allow an
attacker to execute arbitrary commands on the remote system with root
privileges." );
 # nb: http://docs.info.apple.com/article.html?artnum=300667 redirects to http://support.apple.com/kb/HT1646 
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1646" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2004/May/msg00005.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.3.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'AppleFileServer LoginExt PathName Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/03");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/05/28");
 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_end_attributes();

 script_summary(english:"Various flaws in MacOS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("os_fingerprint.nasl");
 script_require_keys("Host/OS");
 exit(0);
}

#

# The Operating system is actually very detailed, because we can read
# its exact version using NTP or RendezVous
os = get_kb_item("Host/OS");
if ( ! os || "Mac OS X" >!< os ) exit(0);

if ( egrep(pattern:"Mac OS X 10\.([01]\.|3\.[0-3])", string:os) )
	security_hole(0);

