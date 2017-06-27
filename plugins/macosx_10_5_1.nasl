#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(28252);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2007-4702", "CVE-2007-4703", "CVE-2007-4704");
 script_bugtraq_id(26459, 26460, 26461);
 script_osvdb_id(40689, 40690, 40691);

 script_name(english:"Mac OS X 10.5.x < 10.5.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5.x that is prior
to 10.5.1.

This update contains several security fixes for the application 
Firewall." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.1 :


http://www.apple.com/support/downloads/macosx1051update.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307004" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/16");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/11/15");
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
script_set_attribute(attribute:"plugin_type", value:"combined");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	os = get_kb_item("Host/OS");
	if (! os ) exit(0);
	conf = get_kb_item("Host/OS/Confidence");
	if ( conf <= 71 ) exit(0);
	}
if ( ereg(pattern:"Mac OS X 10\.5($|\.0)", string:os)) security_warning(0);
