#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(34374);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2007-2691",
    "CVE-2007-4850",
    "CVE-2007-5333",
    "CVE-2007-5342",
    "CVE-2007-5461",
    "CVE-2007-5969",
    "CVE-2007-6286",
    "CVE-2007-6420",
    "CVE-2008-0002",
    "CVE-2008-0226",
    "CVE-2008-0227",
    "CVE-2008-0674",
    "CVE-2008-1232",
    "CVE-2008-1389",
    "CVE-2008-1678",
    "CVE-2008-1767",
    "CVE-2008-1947",
    "CVE-2008-2079",
    "CVE-2008-2364",
    "CVE-2008-2370",
    "CVE-2008-2371",
    "CVE-2008-2712",
    "CVE-2008-2938",
    "CVE-2008-3294",
    "CVE-2008-3432",
    "CVE-2008-3641",
    "CVE-2008-3642",
    "CVE-2008-3643",
    "CVE-2008-3645",
    "CVE-2008-3646",
    "CVE-2008-3647",
    "CVE-2008-3912",
    "CVE-2008-3913",
    "CVE-2008-3914",
    "CVE-2008-4101",
    "CVE-2008-4211",
    "CVE-2008-4212",
    "CVE-2008-4214",
    "CVE-2008-4215"
  );
  script_bugtraq_id(
    24016,
    26070,
    26765,
    27006,
    27140,
    27236,
    27413,
    27703,
    27706,
    27786,
    29106,
    29312,
    29502,
    29653,
    29715,
    30087,
    30279,
    30494,
    30496,
    30633,
    30795,
    30994,
    31051,
    31681,
    31692,
    31707,
    31708,
    31711,
    31715,
    31716,
    31718,
    31719,
    31720,
    31721,
    31722
  );
  script_osvdb_id(
    34766,
    38187,
    39833,
    41195,
    41196,
    41197,
    41434,
    41435,
    41436,
    41935,
    41989,
    42608,
    42937,
    43219,
    44937,
    45419,
    45905,
    46085,
    46306,
    46690,
    47079,
    47462,
    47463,
    47464,
    47810,
    47881,
    48237,
    48238,
    48239,
    48968,
    48969,
    48970,
    48971,
    48973,
    48974,
    48980,
    48986,
    48987,
    48988,
    49130,
    51435,
    51436,
    51437
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-007)");
  script_summary(english:"Check for the presence of Security Update 2008-007");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that
does not have the security update 2008-007 applied. 

This security update contains fixes for the following products :

  - Apache
  - Certificates
  - ClamAV
  - ColorSync
  - CUPS
  - Finder
  - launchd
  - libxslt
  - MySQL Server
  - Networking
  - PHP
  - Postfix
  - PSNormalizer
  - QuickLook
  - rlogin
  - Script Editor
  - Single Sign-On
  - Tomcat
  - vim
  - Weblog" );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3216" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Oct/msg00001.html" );
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-007 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL SSL Hello Message Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(16, 20, 22, 79, 94, 119, 189, 200, 264, 352, 362, 399);
script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/10");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/10/15");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/10/09");
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

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-00[78]|2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-5]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(0);

  if (!egrep(pattern:"^com\.apple\.pkg\.update\.security\.2008\.007\.bom", string:packages))
    security_hole(0);
}

