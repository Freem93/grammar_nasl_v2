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
# This plugin text was extracted from Fedora Security Advisory 2008-10000
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37490);
 script_version ("$Revision: 1.7 $");
script_name(english: "Fedora 10 2008-10000");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10000.");
 script_set_attribute(attribute: "description", value:
"This library allows to manipulate XML files. It includes support
to read, modify and write XML and HTML files. There is DTDs support
this includes parsing and validation even with complex DtDs, either
at parse time or later once the document has been modified. The output
can be a simple SAX stream or and in-memory DOM like representations.
In this case one can use the built-in XPath and XPointer implementation
to select subnodes or ranges. A flexible Input/Output mechanism is
available, with existing HTTP and FTP modules and combined to an
URI library.

Update Information:

Fixes a couple of security issues when overflowing text data size of buffer
size.
");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(59);
script_set_attribute(attribute: "solution", value: "Update the affected package(s) using, for example, 'yum update'.");
script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_cvs_date("$Date: 2012/10/01 00:31:22 $");
script_end_attributes();

 script_cve_id("CVE-2007-1320", "CVE-2008-4225", "CVE-2008-4226", "CVE-2008-4539", "CVE-2008-4989", "CVE-2008-5148");
script_summary(english: "Check for the version of the installed package(s).");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

# Deprecated.
exit(0, "The associated advisory is not security-related.");


include("rpm.inc");

flag = 0;
if ( rpm_check( reference:"cobbler-1.2.9-1.fc10", release:"FC10") ) flag ++;
if ( rpm_check( reference:"drupal-cck-6.x.2.0-3.fc10", release:"FC10") ) flag ++;
if ( rpm_check( reference:"geda-gnetlist-20080929-2.fc10", release:"FC10") ) flag ++;
if ( rpm_check( reference:"gnutls-2.4.2-3.fc10", release:"FC10") ) flag ++;
if ( rpm_check( reference:"kvm-74-6.fc10", release:"FC10") ) flag ++;
if ( rpm_check( reference:"libxml2-2.7.2-2.fc10", release:"FC10") ) flag ++;
if (flag)
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
else
 exit(0, "Host is not affected");
