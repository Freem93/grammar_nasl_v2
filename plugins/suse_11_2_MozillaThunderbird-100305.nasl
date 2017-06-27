
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(45034);
 script_version("$Revision: 1.6 $");
 script_name(english: "SuSE 11.2 Security Update:  MozillaThunderbird (2010-03-05)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaThunderbird");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird was upgraded to version 3.0.3, fixing
various bugs and security issues.

Following security issues have been fixed: MFSA 2010-01 /
CVE-2010-0159: Mozilla developers identified and fixed
several stability bugs in the browser  engine used in
Firefox and other Mozilla-based products. Some of these
crashes showed evidence of memory corruption under certain
circumstances and we presume that with enough effort at
least some of these could be exploited to run arbitrary
code.

MFSA 2010-03 / CVE-2009-1571: Security researcher Alin Rad
Pop of Secunia Research reported that the HTML parser
incorrectly freed used memory when insufficient space was
available to process remaining input. Under such
circumstances, memory occupied by in-use objects was freed
and could later be filled with attacker-controlled text.
These conditions could result in the execution or arbitrary
code if methods on the freed objects were subsequently
called.

MFSA 2009-65 / CVE-2009-3979 / CVE-2009-3980 /
CVE-2009-3982: Crashes with evidence of memory corruption
were fixed. (rv:1.9.1.6)

MFSA 2009-66 / CVE-2009-3388 (bmo#504843,bmo#523816):
Memory safety fixes in liboggplay media library were added.

MFSA 2009-67 / CVE-2009-3389 (bmo#515882,bmo#504613): An
Integer overflow, crash in libtheora video library was
fixed.
");
 script_set_attribute(attribute: "solution", value: "Install the MozillaThunderbird security patch by using 'yast', for example.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(94, 189, 399);
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=576969");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0159");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0160");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1571");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3988");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0162");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/03/11");
 script_cvs_date("$Date: 2016/12/21 20:21:19 $");
script_end_attributes();

 script_cve_id("CVE-2009-1571", "CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3982", "CVE-2010-0159");
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
if ( rpm_check( reference:"MozillaThunderbird-3.0.3-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-3.0.3-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-devel-3.0.3-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-devel-3.0.3-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-common-3.0.3-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-common-3.0.3-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-other-3.0.3-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"MozillaThunderbird-translations-other-3.0.3-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"enigmail-1.0.1-1.1.1", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"enigmail-1.0.1-1.1.1", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"hunspell-1.2.8-2.2", release:"SUSE11.2", cpu:"i586") ) flag ++;
if ( rpm_check( reference:"hunspell-1.2.8-2.2", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if ( rpm_check( reference:"hunspell-32bit-1.2.8-2.2", release:"SUSE11.2", cpu:"x86_64") ) flag ++;
if (flag)
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
else
 exit(0,"Host is not affected");
