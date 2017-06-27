#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# actually a security fix.
#
# Disabled on 2014/11/24.
#


include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if (description)
{
 script_id(40328);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2014/11/24 19:43:36 $");

 script_name(english:"SuSE 11.2 Security Update: update-test-security (2009-05-05) (deprecated)");
 script_summary(english:"Check for the update-test-security package");

 script_set_attribute(attribute:"synopsis", value:
"The remote SuSE system is missing a security patch for
update-test-security");
 script_set_attribute(attribute:"description", value:" - #64937: Release tracking dummy bug for hmuelle");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"solution", value:"Run yast to install the security patch for update-test-security");
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=64937");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");

 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
 script_family(english:"SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not actually a security update.");

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"update-test-security-0-9999.1.2", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
