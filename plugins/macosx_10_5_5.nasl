#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(34211);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2008-0314", 
    "CVE-2008-1100", 
    "CVE-2008-1382", 
    "CVE-2008-1387", 
    "CVE-2008-1447",
    "CVE-2008-1483", 
    "CVE-2008-1657", 
    "CVE-2008-1833", 
    "CVE-2008-1835", 
    "CVE-2008-1836",
    "CVE-2008-1837", 
    "CVE-2008-2305", 
    "CVE-2008-2312", 
    "CVE-2008-2327", 
    "CVE-2008-2329",
    "CVE-2008-2330", 
    "CVE-2008-2331", 
    "CVE-2008-2332", 
    "CVE-2008-2376", 
    "CVE-2008-2713",
    "CVE-2008-3215", 
    "CVE-2008-3608", 
    "CVE-2008-3609", 
    "CVE-2008-3610", 
    "CVE-2008-3611",
    "CVE-2008-3613", 
    "CVE-2008-3614", 
    "CVE-2008-3616", 
    "CVE-2008-3617", 
    "CVE-2008-3618",
    "CVE-2008-3619", 
    "CVE-2008-3621", 
    "CVE-2008-3622"
  );
  script_bugtraq_id(
    28444, 
    28531, 
    28756, 
    28770, 
    28784, 
    29750, 
    30131, 
    30832, 
    31086, 
    31189
  );
  script_osvdb_id(
    43745,
    43911,
    44364,
    44370,
    44519,
    44520,
    44521,
    44522,
    44523,
    44524,
    46241,
    46691,
    46776,
    47156,
    47795,
    48034,
    48180,
    48181,
    48182,
    48183,
    48184,
    48185,
    48186,
    48187,
    48188,
    48189,
    48190,
    48191,
    48192,
    48193,
    48194,
    48195,
    48235,
    48236,
    48245,
    53530
  );
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Mac OS X 10.5.x < 10.5.5 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5.x that is prior
to 10.5.5. 

Mac OS X 10.5.5 contains security fixes for a number of programs." );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3137" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00005.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 119, 189, 200, 255, 264, 287, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/16");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/09/15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (ereg(pattern:"Mac OS X 10\.5\.[0-4]([^0-9]|$)", string:os)) security_hole(0);
