#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(30254);
  script_version ("$Revision: 1.23 $");

  if (NASL_LEVEL >= 3000)
  {
    script_cve_id("CVE-2007-0355", "CVE-2007-4568", "CVE-2007-6015", "CVE-2008-0035", "CVE-2008-0037",
                  "CVE-2008-0038", "CVE-2008-0039", "CVE-2008-0040", "CVE-2008-0041", "CVE-2008-0042");
    script_bugtraq_id(22101, 25898, 26791, 27296, 27736);
  script_osvdb_id(
    32693,
    37721,
    39191,
    40891,
    41503,
    41504,
    41505,
    41506,
    41507,
    41508
  );
  script_xref(name:"EDB-ID", value:"3151");
  }

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-001)");
  script_summary(english:"Check for the presence of Security Update 2008-001");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have the security update 2008-001 applied. 

This update contains several security fixes for a number of programs." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307430" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00002.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/13987" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-001 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94, 119, 189, 200, 264, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/02/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/17");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(0);

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-00[1-8]|2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
