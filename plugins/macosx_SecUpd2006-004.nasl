#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22125);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/09/26 13:31:37 $");

  script_cve_id("CVE-2005-0488", "CVE-2005-0988", "CVE-2005-1228", "CVE-2005-2335", "CVE-2005-3088",
                "CVE-2005-4348", "CVE-2006-0321", "CVE-2006-0392", "CVE-2006-0393", "CVE-2006-1472",
                "CVE-2006-1473", "CVE-2006-3459", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3465",
                "CVE-2006-3495", "CVE-2006-3496", "CVE-2006-3497", "CVE-2006-3498", "CVE-2006-3499",
                "CVE-2006-3500", "CVE-2006-3501", "CVE-2006-3502", "CVE-2006-3503", "CVE-2006-3504",
                "CVE-2006-3505");
  script_bugtraq_id(19289);
  script_osvdb_id(
   15487,
   15721,
   17303,
   18174,
   20267,
   21906,
   22691,
   26930,
   27723,
   27725,
   27726,
   27729,
   27731,
   27732,
   27733,
   27735,
   27736,
   27737,
   27738,
   27739,
   27740,
   27741,
   27742,
   27743,
   27744,
   27745
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-004)");
  script_summary(english:"Check for Security Update 2006-004");

  script_set_attribute(attribute:"synopsis", value:"The remote operating system is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks
Security Update 2006-004.

This security update contains fixes for the following
applications :

AFP Server
Bluetooth
Bom
DHCP
dyld
fetchmail
gnuzip
ImageIO
LaunchServices
OpenSSH
telnet
WebKit");
 # http://web.archive.org/web/20070728033955/http://docs.info.apple.com/article.html?artnum=304063
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e97e41a");
  script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :

http://www.apple.com/support/downloads/securityupdate2006004macosx1047clientintel.html
http://www.apple.com/support/downloads/securityupdate2006004macosx1047clientppc.html

Mac OS X 10.3 :

http://www.apple.com/support/downloads/securityupdate20060041039client.html
http://www.apple.com/support/downloads/securityupdate20060041039server.html");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iOS MobileMail LibTIFF Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"MacOS X Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");
  exit(0);
}

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-7]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-00[467]|2007-00[38])", string:packages)) security_hole(0);
}
