#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if ( NASL_LEVEL < 3004 ) exit(0);



include("compat.inc");

if (description)
{
  script_id(33281);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2005-3164", "CVE-2007-1355", "CVE-2007-2449", "CVE-2007-2450", "CVE-2007-3382",
                "CVE-2007-3383", "CVE-2007-3385", "CVE-2007-5333", "CVE-2007-5461", "CVE-2007-6276",
                "CVE-2008-0960", "CVE-2008-1105", "CVE-2008-1145", "CVE-2008-2307", "CVE-2008-2308",
                "CVE-2008-2309", "CVE-2008-2310", "CVE-2008-2311", "CVE-2008-2313", "CVE-2008-2314",
                "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_bugtraq_id(15003, 24058, 24475, 24476, 24999, 25316, 26070, 26699, 27706,
                    28123, 29404, 29623, 29836, 30018);
  script_osvdb_id(
    19821,
    34875,
    36079,
    36080,
    37070,
    37071,
    38187,
    39000,
    40278,
    41435,
    42615,
    42616,
    45657,
    46059,
    46502,
    46550,
    46551,
    46552,
    46553,
    46554,
    46663,
    46664,
    46665,
    46666,
    46667,
    46668,
    46669
  );
  script_xref(name:"Secunia", value:"30802");

  script_name(english:"Mac OS X 10.5.x < 10.5.4 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5.x that is prior
to 10.5.4. 

Mac OS X 10.5.4 contains security fixes for multiple components.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT2163" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Jun/msg00002.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 59, 79, 119, 134, 189, 200, 264, 287, 362, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/01");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/30");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/06/30");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(0);

if (ereg(pattern:"Mac OS X 10\.5\.[0-3]([^0-9]|$)", string:os)) security_hole(0);
