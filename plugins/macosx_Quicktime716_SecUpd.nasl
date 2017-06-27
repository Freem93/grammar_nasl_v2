#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(25346);
 script_version ("$Revision: 1.12 $");

 script_cve_id("CVE-2007-2388", "CVE-2007-2389");
 script_bugtraq_id(24221, 24222);
 script_osvdb_id(35575, 35576);

 script_name(english:"Quicktime Multiple Vulnerabilities (Mac OS X 7.1.6 Security Update)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of Quicktime on the remote
Mac OS X host that contains a bug which might allow a rogue Java 
program to write anywhere in the heap.

An attacker may be able to leverage these issues to execute arbitrary 
code on the remote host by luring a victim into visiting a rogue page
containing a malicious Java applet." );
 # http://web.archive.org/web/20070714134644/http://docs.info.apple.com/article.html?artnum=305531
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f11b9bd" );
 script_set_attribute(attribute:"solution", value:
"Install the Quicktime 7.1.6 Security Update." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/05/19");
 script_cvs_date("$Date: 2013/03/04 23:24:26 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

 script_summary(english:"Check for Quicktime 7.1.6 Security Update");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);



version = split(ver, sep:'.', keep:FALSE);
if ( (int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) == 6) )
{
 if ( ! egrep(pattern:"^SecUpdQuickTime716\.pkg", string:packages) )
	security_hole(0);
}
