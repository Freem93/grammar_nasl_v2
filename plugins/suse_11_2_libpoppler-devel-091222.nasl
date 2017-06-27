
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(43618);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.2 Security Update:  libpoppler-devel (2009-12-22)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for libpoppler-devel");
 script_set_attribute(attribute: "description", value: "This update of libpoppler5 fixes various security issues.

CVE-2009-0791: Fix multiple integer overflows in 'pdftops'
filter that could be used by attackers to execute code.

CVE-2009-3607: Integer overflow in the
create_surface_from_thumbnail_data function in
glib/poppler-page.cc in Poppler 0.x allows remote attackers
to cause a denial of service (memory corruption) or
possibly execute arbitrary code via a crafted PDF document
that triggers a heap-based buffer overflow. NOTE: some of
these details are obtained from third party information. 

CVE-2009-3608: Integer overflow in the
ObjectStream::ObjectStream function in XRef.cc in Xpdf 3.x
before 3.02pl4 and Poppler before 0.12.1, as used in GPdf,
kdegraphics KPDF, CUPS pdftops, and teTeX, might allow
remote attackers to execute arbitrary code via a crafted
PDF document that triggers a heap-based buffer overflow. 

CVE-2009-3938: Buffer overflow in the ABWOutputDev::endWord
function in poppler/ABWOutputDev.cc in Poppler (aka
libpoppler) 0.10.6, 0.12.0, and possibly other versions, as
used by the Abiword pdftoabw utility, allows user-assisted
remote attackers to cause a denial of service and possibly
execute arbitrary code via a crafted PDF file. 

CVE-2009-4035: A indexing error in FoFiType1::parse() was
fixed that could be used by attackers to corrupt memory and
potentially execute code.
");
 script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for libpoppler-devel");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cwe_id(94, 119, 189);
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=537171");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=543090");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=546393");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=507102");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=556876");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=556607");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0791");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3608");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3607");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3938");
script_set_attribute(attribute: "see_also", value: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-4035");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/01/03");
 script_cvs_date("$Date: 2016/12/21 20:21:19 $");
script_end_attributes();

 script_cve_id("CVE-2009-0791", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3938", "CVE-2009-4035");
script_summary(english: "Check for the libpoppler-devel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libpoppler-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-doc-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-doc-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-glib-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-glib-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-glib4-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-glib4-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt2-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt2-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt3-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt3-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt4-3-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt4-3-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt4-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler-qt4-devel-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler5-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libpoppler5-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"poppler-tools-0.12.0-2.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"poppler-tools-0.12.0-2.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
