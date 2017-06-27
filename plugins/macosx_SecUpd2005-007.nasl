#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if(description)
{
 script_id(19463);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/11/14 18:38:13 $");

 script_cve_id("CVE-2005-1344", "CVE-2004-0942", "CVE-2004-0885", "CVE-2004-1083", "CVE-2004-1084",
               "CVE-2005-2501", "CVE-2005-2502", "CVE-2005-2503", "CVE-2005-2504", "CVE-2005-2505",
               "CVE-2005-2506", "CVE-2005-2525", "CVE-2005-2526", "CVE-2005-2507", "CVE-2005-2508",
               "CVE-2005-2519", "CVE-2005-2513", "CVE-2004-1189", "CVE-2005-1174", "CVE-2005-1175",
               "CVE-2005-1689", "CVE-2005-2511", "CVE-2005-2509", "CVE-2005-2512", "CVE-2005-2745",
               "CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711", "CVE-2004-0079", "CVE-2004-0112",
               "CVE-2005-2514", "CVE-2005-2515", "CVE-2005-2516", "CVE-2005-2517", "CVE-2005-2524",
               "CVE-2005-2520", "CVE-2005-2518", "CVE-2005-2510", "CVE-2005-1769", "CVE-2005-2095",
               "CVE-2005-2521", "CVE-2005-2522", "CVE-2005-2523", "CVE-2005-0605", "CVE-2005-2096",
               "CVE-2005-1849");
 script_bugtraq_id(14567, 14569);
 script_osvdb_id(
  4316,
  4317,
  10637,
  11391,
  12192,
  12193,
  12533,
  12848,
  14373,
  14676,
  14677,
  14678,
  17360,
  17361,
  17827,
  17841,
  17842,
  17843,
  17873,
  17874,
  18141,
  18774,
  18775,
  18776,
  18777,
  18778,
  18779,
  18780,
  18781,
  18782,
  18783,
  18784,
  18785,
  18786,
  18787,
  18788,
  18789,
  18790,
  18791,
  18792,
  18793,
  18794,
  18795,
  18796,
  18797,
  18983,
  19705,
  19709,
  97353
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-007)");
 script_summary(english:"Check for Security Update 2005-007");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description",  value:
"The remote host is running a version of Mac OS X 10.4 or 10.3 that
does not have Security Update 2005-007 applied.

This security update contains fixes for the following products :

  - Apache 2
  - AppKit
  - Bluetooth
  - CoreFoundation
  - CUPS
  - Directory Services
  - HItoolbox
  - Kerberos
  - loginwindow
  - Mail
  - MySQL
  - OpenSSL
  - QuartzComposerScreenSaver
  - ping
  - Safari
  - SecurityInterface
  - servermgrd
  - servermgr_ipfilter
  - SquirelMail
  - traceroute
  - WebKit
  - WebLog Server
  - X11
  - zlib" );
  # http://web.archive.org/web/20060406190355/http://docs.info.apple.com/article.html?artnum=302163
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?74ffa359"
  );
 script_set_attribute(attribute:"solution", value:
"!Install Security Update 2005-007." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/08/12");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
# MacOS X 10.4.2
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.2\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-007", string:packages)) security_hole(0);
}
