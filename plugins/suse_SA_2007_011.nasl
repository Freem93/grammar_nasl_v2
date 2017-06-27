#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:011
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24464);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2007:011: acroread";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:011 (acroread).


The Adobe Acrobat Reader has been updated to version 7.0.9.

This update also includes following security fixes:

CVE-2006-5857: A memory corruption problem was fixed in Adobe Acrobat
Reader can potentially lead to code execution.

CVE-2007-0044: Universal Cross Site Request Forgery (CSRF) problems
		  were fixed in the Acrobat Reader plugin which could be
		  exploited by remote attackers to conduct CSRF attacks
		  using any site that is providing PDFs.

CVE-2007-0045: Cross site scripting problems in the Acrobat Reader
		  plugin were fixed, which could be exploited by remote
		  attackers to conduct XSS attacks against any site that
		  is providing PDFs.

CVE-2007-0046: A double free problem in the Acrobat Reader plugin was fixed
which could be used by remote attackers to potentially execute
	          arbitrary code.
	          Note that all platforms using Adobe Reader currently have
	          counter measures against such attack where it will just
	          cause a controlled abort().

Please note that the Acrobat Reader on SUSE Linux Enterprise Server
9 is affected too, but can not be updated currently due to GTK+
2.4 requirements.  We are trying to find a solution.

Acrobat Reader on SUSE Linux Enterprise Server 8 and SUSE Linux
Desktop 1 is no longer supported and should be deinstalled." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_11_acroread.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the acroread package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"acroread-7.0.9-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.9-2.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
