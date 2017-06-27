#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21073);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/03/06 01:32:41 $");

 script_cve_id("CVE-2006-0400", "CVE-2006-0396", "CVE-2006-0397", "CVE-2006-0398", "CVE-2006-0399");
 script_bugtraq_id(17081);
 script_osvdb_id(23869, 23870, 23871, 23872, 23873);

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-002)");
 script_summary(english:"Check for Security Update 2006-002");

 script_set_attribute(attribute:"synopsis", value:"The remote operating system is missing a vendor-supplied patch.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks
Security Update 2006-002.

This security update contains fixes for the following
applications :

apache_mod_php
CoreTypes
LaunchServices
Mail
Safari
rsync");
 # http://web.archive.org/web/20060418210702/http://docs.info.apple.com/article.html?artnum=303453
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12789989");
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
# http://web.archive.org/web/20060314170904/http://www.apple.com/support/downloads/securityupdate2006002macosx1045ppc.html
  http://www.nessus.org/u?37e197d3

Mac OS X 10.3 :
# http://web.archive.org/web/20060314170813/http://www.apple.com/support/downloads/securityupdate20060021039client.html
http://www.nessus.org/u?abc4e668
http://www.apple.com/support/downloads/securityupdate20060021039server.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/03/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-5]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-00[23467]|2007-003)", string:packages)) security_hole(0);
}
