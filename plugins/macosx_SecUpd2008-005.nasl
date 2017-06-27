#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(33790);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2007-4850", 
    "CVE-2007-5135", 
    "CVE-2007-6199", 
    "CVE-2007-6200", 
    "CVE-2008-0599",
    "CVE-2008-0674", 
    "CVE-2008-1447", 
    "CVE-2008-2050", 
    "CVE-2008-2051", 
    "CVE-2008-2320",
    "CVE-2008-2321", 
    "CVE-2008-2322", 
    "CVE-2008-2323", 
    "CVE-2008-2324", 
    "CVE-2008-2325",
    "CVE-2008-2830", 
    "CVE-2008-2952"
  );
  script_bugtraq_id(
    25831, 
    26638, 
    26639, 
    27413, 
    27786, 
    29009, 
    29831, 
    30013, 
    30131, 
    30487,
    30488, 
    30489, 
    30490, 
    30492, 
    30493
  );
  script_osvdb_id(
    29262,
    39593,
    39594,
    41989,
    43219,
    44906,
    44907,
    44908,
    46490,
    46689,
    46776,
    48186,
    48564,
    48565,
    48566,
    48567,
    48568,
    48569
  );
  script_xref(name:"Secunia", value:"31326");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-005)");
  script_summary(english:"Check for the presence of Security Update 2008-005");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that
does not have the security update 2008-005 applied. 

This update contains security fixes for a number of programs." );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT2647" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Jul/msg00003.html" );
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-005 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/01");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/07/31");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-00[5-8]||2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-4]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(0);

  if (!egrep(pattern:"^com\.apple\.pkg\.update\.security\.2008\.005\.bom", string:packages))
    security_hole(0);
}
