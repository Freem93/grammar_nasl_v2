#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(22479);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");

 script_cve_id("CVE-2006-1721", "CVE-2006-3311", "CVE-2006-3587", "CVE-2006-3588", "CVE-2006-3946",
               "CVE-2006-4387", "CVE-2006-4390", "CVE-2006-4391", "CVE-2006-4392", "CVE-2006-4393",
               "CVE-2006-4394", "CVE-2006-4395", "CVE-2006-4397", "CVE-2006-4399", "CVE-2006-4640");
 script_bugtraq_id(20271);
 script_osvdb_id(
  24510,
  27113,
  27534,
  28732,
  28733,
  28734,
  29267,
  29268,
  29269,
  29270,
  29271,
  29272,
  29273,
  29274,
  29276
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-006)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.3 which does not have
the security update 2006-006 applied.

Security Update 2006-006 contains several security fixes for the following 
programs :

 - CFNetwork
 - Flash Player
 - QuickDraw Manager
 - SASL
 - WebCore" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.8 :
http://www.apple.com/support/downloads/macosx1048updateintel.html
http://www.apple.com/support/downloads/macosx1048updateppc.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304460" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/31");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/09/29");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl", "ntp_open.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* 7\.[0-9]\.", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-00[67]|2007-003)", string:packages)) security_hole(0);
}
