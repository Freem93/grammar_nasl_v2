
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42395);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.2 Security Update:  kmps (2009-10-28)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kmps");
 script_set_attribute(attribute: "description", value: "This update contains kernel module packages for the
openSUSE 11.2 RC1 test kernel update.

It contains all kernel module packages.
");
 script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kmps");
 script_set_attribute(attribute:"risk_factor", value:"High");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=546918");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/11/05");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");
script_end_attributes();

script_summary(english: "Check for the kmps package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-default-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-default-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-desktop-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-desktop-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-pae-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-xen-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-xen-1.1.0.2_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-debug-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-debug-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-default-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-default-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-desktop-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-desktop-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-pae-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-xen-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compcache-kmp-xen-0.5.3_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-debug-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-debug-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-default-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-default-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-desktop-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-desktop-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-pae-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-xen-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-xen-2.3.7_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-debug-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-debug-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-default-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-default-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-desktop-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-desktop-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-pae-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-xen-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-xen-8.3.4_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-debug-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-debug-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-default-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-default-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-desktop-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-desktop-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-pae-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-xen-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-xen-0.4.17_2.6.31.5_0.1-4.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-default-0.8.5_2.6.31.5_0.1-0.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-default-0.8.5_2.6.31.5_0.1-0.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-desktop-0.8.5_2.6.31.5_0.1-0.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-desktop-0.8.5_2.6.31.5_0.1-0.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-pae-0.8.5_2.6.31.5_0.1-0.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-xen-0.8.5_2.6.31.5_0.1-0.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-xen-0.8.5_2.6.31.5_0.1-0.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-default-1.55_2.6.31.5_0.1-3.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-default-1.55_2.6.31.5_0.1-3.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-desktop-1.55_2.6.31.5_0.1-3.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-desktop-1.55_2.6.31.5_0.1-3.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-pae-1.55_2.6.31.5_0.1-3.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-xen-1.55_2.6.31.5_0.1-3.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-xen-1.55_2.6.31.5_0.1-3.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-debug-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-debug-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-default-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-default-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-desktop-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-desktop-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-pae-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-xen-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-xen-20080627_2.6.31.5_0.1-2.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-debug-0.44_2.6.31.5_0.1-241.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-debug-0.44_2.6.31.5_0.1-241.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-default-0.44_2.6.31.5_0.1-241.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-default-0.44_2.6.31.5_0.1-241.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-desktop-0.44_2.6.31.5_0.1-241.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-desktop-0.44_2.6.31.5_0.1-241.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-pae-0.44_2.6.31.5_0.1-241.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"preload-kmp-default-1.1_2.6.31.5_0.1-6.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"preload-kmp-default-1.1_2.6.31.5_0.1-6.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"preload-kmp-desktop-1.1_2.6.31.5_0.1-6.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"preload-kmp-desktop-1.1_2.6.31.5_0.1-6.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-debug-3.0.6_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-debug-3.0.6_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-default-3.0.6_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-default-3.0.6_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-desktop-3.0.6_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-desktop-3.0.6_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-pae-3.0.6_2.6.31.5_0.1-9.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-guest-kmp-debug-2009.07.22_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-guest-kmp-debug-2009.07.22_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-guest-kmp-default-2009.07.22_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-guest-kmp-default-2009.07.22_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-guest-kmp-desktop-2009.07.22_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-guest-kmp-desktop-2009.07.22_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-guest-kmp-pae-2009.07.22_2.6.31.5_0.1-2.4.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-debug-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-debug-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-default-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-default-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-desktop-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-desktop-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-pae-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-xen-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-xen-0.8.1_2.6.31.5_0.1-6.1.4", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
