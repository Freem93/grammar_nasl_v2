
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(47678);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE 11.2 Security Update:  MozillaThunderbird (2010-06-22)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaThunderbird");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird was updated to version 3.0.5, fixing
lots of security issues.

Mozilla has so far not communicated what vulnerabilities
were fixed, the list will appear on:
http://www.mozilla.org/security/known-vulnerabilities/thunde
rbird30.html
");
 script_set_attribute(attribute: "solution", value: "Install the MozillaThunderbird security patch by using 'yast', for example.");
 script_set_attribute(attribute:"risk_factor", value:"High");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=603356");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/08");
 script_cvs_date("$Date: 2016/12/21 20:21:19 $");
script_end_attributes();

script_summary(english: "Check for the MozillaThunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

flag = 0;
if ( rpm_check( reference:"MozillaThunderbird-3.0.5-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-3.0.5-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-devel-3.0.5-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-devel-3.0.5-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-common-3.0.5-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-common-3.0.5-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-other-3.0.5-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-other-3.0.5-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"enigmail-1.0.1-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"enigmail-1.0.1-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if (flag)
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
else
 exit(0,"Host is not affected");
