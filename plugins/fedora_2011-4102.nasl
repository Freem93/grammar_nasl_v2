# @DEPRECATED@
#
# This script has been deprecated as the associated advisory is not
# security-related.
#
# Disabled on 2012/09/30.
#


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2011-4102
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(53308);
 script_version("$Revision: 1.2 $");
script_name(english: "Fedora 13 2011-4102");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2011-4102.");
 script_set_attribute(attribute: "description", value:
"PEAR is a framework and distribution system for reusable PHP
components.  This package contains the basic PEAR components.

Update Information:

According to https://fedorahosted.org/fpc/ticket/69 and to new PHP Guidelines, move %{pear_docdir} (/usr/share/pear/doc) to %{_docdir}/pear (/usr/share/doc/pear)

Upstream Changelog:

Important! This is a security fix release. The advisory can be found at http://pear.php.net/advisory-20110228.txt

Bugs:

Update information :

* Fixed Bug #17463: Regression: On Windows, svntag [patch by doconnor]
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Update the affected package(s) using, for example, 'yum update'.");
script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/07");
 script_cvs_date("$Date: 2012/10/01 00:31:22 $");
script_end_attributes();

script_summary(english: "Check for the version of the installed package(s).");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english: "This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

# Deprecated.
exit(0, "The associated advisory is not security-related.");


include("rpm.inc");

flag = 0;
if ( rpm_check( reference:"php-pear-1.9.2-3.fc13", release:"FC13") ) flag ++;
if (flag)
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
else
 exit(0, "Host is not affected");
