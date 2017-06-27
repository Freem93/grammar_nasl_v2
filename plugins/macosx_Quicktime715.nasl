#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(24762);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2007-0712", "CVE-2007-0713", "CVE-2007-0714", "CVE-2007-0715",
               "CVE-2007-0716", "CVE-2007-0717", "CVE-2007-0718");
 script_bugtraq_id(22827);
 script_osvdb_id(33898, 33899, 33900, 33901, 33902, 33903, 33904);

 script_name(english:"Quicktime < 7.1.5 Multiple Vulnerabilities (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of Quicktime on the remote
Mac OS X host is affected by multiple buffer overflows.  An attacker
may be able to leverage these issues to crash the affected application
or to execute arbitrary code on the remote host by sending a
specially crafted file to a victim and having him open it using
QuickTime." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305149" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Quicktime version 7.1.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/19");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/03/05");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

 script_summary(english:"Check for Quicktime 7.1.5");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( (int(version[0]) < 7) ||
     (int(version[0]) == 7 && int(version[1]) == 0 ) ||
     (int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 5) ) security_hole(0);
