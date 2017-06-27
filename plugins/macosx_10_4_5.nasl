#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(20911);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2006-0382");
 script_bugtraq_id(16654);
 script_osvdb_id(23190);

 script_name(english:"Mac OS X 10.4.x < 10.4.5 Kernel Undocumented System Call Local DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4.x that is prior
to 10.4.5.

Mac OS X 10.4.5 contains a security fix for a local denial of service 
vulnerability. A malicious local user may trigger the vulnerability by 
invoking an undocumented system call." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.5 :
http://www.apple.com/support/downloads/macosxupdate1045.html
http://www.apple.com/support/downloads/macosxserver1045.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 # http://web.archive.org/web/20060405112613/http://docs.info.apple.com/article.html?artnum=61798
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f26343c2" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/02/14");
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-4]([^0-9]|$))", string:os )) security_note(0);
