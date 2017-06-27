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
# This plugin text was extracted from Fedora Security Advisory 2012-9621
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(59803);
 script_version("$Revision: 1.2 $");
script_name(english: "Fedora 17 2012-9621");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2012-9621.");
 script_set_attribute(attribute: "description", value:
"
Cobbler is a network install server.  Cobbler supports PXE,
virtualized installs, and re-installing existing Linux machines.  The
last two modes use a helper tool, 'koan', that integrates with
cobbler.  There is also a web interface 'cobbler-web'.  Cobbler's
advanced features include importing distributions from DVDs and rsync
mirrors, kickstart templating, integrated yum mirroring, and built-in
DHCP/DNS Management.  Cobbler has a XMLRPC API for integration with
other applications.

Update Information:

New upstream release
New upstream release - 2.2.3-1
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Update the affected package(s) using, for example, 'yum update'.");
script_set_attribute(attribute:"plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/01");
  script_cvs_date("$Date: 2012/10/01 00:31:22 $");
script_end_attributes();

script_summary(english: "Check for the version of the installed package(s).");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english: "This script is Copyright (C) 2012 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

# Deprecated.
exit(0, "The associated advisory is not security-related.");


include("rpm.inc");

flag = 0;
if ( rpm_check( reference:"cobbler-2.2.3-2.fc17", release:"FC17") ) flag ++;
if (flag)
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
else
 exit(0, "Host is not affected");
