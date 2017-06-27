#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3004) exit(1);

include("compat.inc");

if(description)
{
 script_id(17218);
 script_version("$Revision: 1.26 $");

 script_cve_id(
   "CVE-2004-1200", 
   "CVE-2005-0230", 
   "CVE-2005-0233", 
   "CVE-2005-0255",
   "CVE-2005-0578", 
   "CVE-2005-0584", 
   "CVE-2005-0586", 
   "CVE-2005-0587",
   "CVE-2005-0588", 
   "CVE-2005-0589", 
   "CVE-2005-0590", 
   "CVE-2005-0591",
   "CVE-2005-0592", 
   "CVE-2005-0593"
 );
 script_bugtraq_id(
   12533, 
   12461, 
   12470, 
   12468, 
   12466, 
   12465, 
   12234,
   12153, 
   11854, 
   11823, 
   11752, 
   12655, 
   12659, 
   12728
 );
 script_osvdb_id(
  11151,
  12868,
  13578,
  13610,
  14185,
  14187,
  14188,
  14189,
  14190,
  14191,
  14192,
  14193,
  14194,
  14195,
  14196,
  14198
 );

 script_name(english:"Firefox < 1.0.1 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Firefox");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The installed version of Firefox is earlier than 1.0.1.  Such
versions have multiple security issues, including vulnerabilities
that could allow an attacker to impersonate a website by using an
International Domain Name, or vulnerabilities that could allow
arbitrary code execution." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/known-vulnerabilities/firefox10.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 1.0.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/23");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/02/25");
 script_cvs_date("$Date: 2013/05/23 15:37:57 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

#
include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.0.1', severity:SECURITY_HOLE);