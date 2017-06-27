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
 script_id(13664);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "Fedora Core 1 2003-026-1: kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2003-026-1 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Red Hat Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.


THIS IS NOT AN OFFICIAL ANNOUNCEMENT FROM FEDORA PROJECT.
WE HAVE NOT RECEIVED THE OFFICIAL ANNOUNCEMENT AS OF 4:37PM 12/24/03 YET
WE WILL REPLACE WITH THE OFFICIAL ANNOUNCMENT AS SOON AS WE RECEIVE.
IN THE MEANTIME, HERE IS WHAT HAS CHANGED SINCE LAST KERNEL UPDATE ON 12/02/03" );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2003-026-1.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/23");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kernel package";
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
if ( rpm_check( reference:"kernel-2.4.22-1.2135.nptl", prefix:"kernel-", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
