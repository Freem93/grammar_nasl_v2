#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if ( NASL_LEVEL < 3004 ) exit(0);



include("compat.inc");

if (description)
{
  script_id(32477);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2005-3352", "CVE-2005-3357", "CVE-2006-3747", "CVE-2007-0071", "CVE-2007-1863",
                "CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-5266", "CVE-2007-5268",
                "CVE-2007-5269", "CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6359", "CVE-2007-6388",
                "CVE-2007-6612", "CVE-2008-0177", "CVE-2008-1027", "CVE-2008-1028", "CVE-2008-1030",
                "CVE-2008-1031", "CVE-2008-1032", "CVE-2008-1033", "CVE-2008-1034", "CVE-2008-1035",
                "CVE-2008-1036", "CVE-2008-1571", "CVE-2008-1572", "CVE-2008-1573", "CVE-2008-1574",
                "CVE-2008-1575", "CVE-2008-1576", "CVE-2008-1577", "CVE-2008-1578", "CVE-2008-1579",
                "CVE-2008-1580", "CVE-2008-1654", "CVE-2008-1655");
  script_bugtraq_id("15834", "25489", "25957", "26840", "26930", "27133", "27642", "28633",
                    "28694", "29480", "29481", "29483", "29484", "29486", "29487", "29488",
                    "29489", "29490", "29491", "29492", "29493", "29500", "29501", "29511",
                    "29513", "29514", "29520", "29521");
  script_osvdb_id(
    21705,
    22261,
    27588,
    37051,
    37079,
    38272,
    38273,
    38274,
    38636,
    39133,
    39134,
    39866,
    40262,
    40694,
    41111,
    41489,
    43979,
    44279,
    44282,
    44283,
    45690,
    45694,
    45695,
    45696,
    45697,
    45698,
    45699,
    45700,
    45701,
    45702,
    45703,
    45704,
    45705,
    45706,
    45707,
    45708,
    45709,
    45710,
    45711
  );
  script_xref(name:"Secunia", value:"30430");

  script_name(english:"Mac OS X 10.5.x < 10.5.3 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5.x that is prior
to 10.5.3. 

Mac OS X 10.5.3 contains security fixes for a number of programs." );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1897" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/May/msg00001.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/14755" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Module mod_rewrite LDAP Protocol Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 22, 79, 94, 119, 189, 200, 264, 352, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/29");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/13");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/05/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(0);

if (ereg(pattern:"Mac OS X 10\.5\.[0-2]([^0-9]|$)", string:os)) security_hole(0);
