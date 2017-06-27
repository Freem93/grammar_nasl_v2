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
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13681);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "Fedora Core 1 2004-087: libxml2";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-087 (libxml2).

This library allows to manipulate XML files. It includes support
to read, modify and write XML and HTML files. There is DTDs support
this includes parsing and validation even with complex DtDs, either
at parse time or later once the document has been modified. The output
can be a simple SAX stream or and in-memory DOM like representations.
In this case one can use the built-in XPath and XPointer implementation
to select subnodes or ranges. A flexible Input/Output mechanism is
available, with existing HTTP and FTP modules and combined to an
URI library.

Update Information:

Updated libxml2 packages are available to fix an overflow when parsing
the URI for remote resources." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-087.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/23");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the libxml2 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

# Deprecated.
exit(0, "The associated advisory is not security-related.");


include("rpm.inc");
if ( rpm_check( reference:"libxml2-2.6.6-3", prefix:"libxml2-", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
