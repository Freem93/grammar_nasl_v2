#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:003
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20758);
 script_bugtraq_id(16325);
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "SUSE-SA:2006:003: kdelibs3";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:003 (kdelibs3).


Maksim Orlovich discovered a bug in the JavaScript interpreter used
by Konqueror. UTF-8 encoded URLs could lead to a buffer overflow
that causes the browser to crash or execute arbitrary code.
Attackers could trick users into visiting specially crafted web
sites that exploit this bug (CVE-2006-0019)." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_03_kdelibs3.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/21");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kdelibs3 package";
 script_cve_id("CVE-2006-0019");
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdelibs3-3.4.2-24.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.4.2-24.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.2.1-44.65", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.2.1-44.65", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.3.0-34.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.3.0-34.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.4.0-20.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.4.0-20.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
