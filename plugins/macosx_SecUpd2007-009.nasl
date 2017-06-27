#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29723);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2006-0024", "CVE-2007-1218", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661",
                "CVE-2007-1662", "CVE-2007-3798", "CVE-2007-3876", "CVE-2007-4131", "CVE-2007-4351",
                "CVE-2007-4572", "CVE-2007-4708", "CVE-2007-4709", "CVE-2007-4710", "CVE-2007-4766",
                "CVE-2007-4767", "CVE-2007-4768", "CVE-2007-4965", "CVE-2007-5116", "CVE-2007-5379",
                "CVE-2007-5380", "CVE-2007-5398", "CVE-2007-5476", "CVE-2007-5770", "CVE-2007-5847",
                "CVE-2007-5848", "CVE-2007-5849", "CVE-2007-5850", "CVE-2007-5851", "CVE-2007-5853",
                "CVE-2007-5854", "CVE-2007-5855", "CVE-2007-5856", "CVE-2007-5857", "CVE-2007-5858",
                "CVE-2007-5859", "CVE-2007-5860", "CVE-2007-5861", "CVE-2007-5863", "CVE-2007-6077",
                "CVE-2007-6165");
  script_bugtraq_id(17106, 22772, 24965, 25417, 25696, 26096, 26268, 26274, 26346,
                    26350, 26421, 26454, 26455, 26510, 26598, 26908, 26910, 26926);
  script_osvdb_id(
    23908,
    32427,
    38128,
    38183,
    38213,
    39179,
    39180,
    39193,
    40142,
    40409,
    40717,
    40718,
    40719,
    40720,
    40721,
    40722,
    40723,
    40724,
    40725,
    40726,
    40727,
    40728,
    40729,
    40730,
    40731,
    40732,
    40733,
    40734,
    40735,
    40736,
    40737,
    40738,
    40759,
    40760,
    40761,
    40763,
    40764,
    40765,
    40766,
    40773,
    40875,
    42028
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2007-009)");
  script_summary(english:"Check for the presence of Security Update 2007-009");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that does
not have Security Update 2007-009 applied. 

This update contains several security fixes for a large number of
programs.");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307179");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/Dec/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/13649");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2007-009.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mail.app Image Attachment Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(16, 20, 22, 79, 119, 134, 189, 200, 264, 287, 310, 362, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}


uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);
if ( egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname) )
{
  packages = get_kb_item("Host/MacOSX/packages");
  if ( ! packages ) exit(0);
  if (!egrep(pattern:"^SecUpd(Srvr)?(2007-009|200[89]-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
else if ( egrep(pattern:"Darwin.* (9\.[01]\.)", string:uname) )
{
 packages = get_kb_item("Host/MacOSX/packages/boms");
 if ( ! packages ) exit(0);
 if ( !egrep(pattern:"^com\.apple\.pkg\.update\.security\.2007\.009\.bom", string:packages) )
	security_hole(0);
}
