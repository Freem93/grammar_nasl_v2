#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:040
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24420);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:040: OpenOffice_org";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:040 (OpenOffice_org).


Following security problems were found and fixed in OpenOffice_org:

- CVE-2006-2198:

A security vulnerability in OpenOffice.org may make it possible to
inject basic code into documents which is executed upon loading
of the document. The user will not be asked or notified and the
macro will have full access to system resources with current user's
privileges. As a result, the macro may delete/replace system files,
read/send private data and/or cause additional security issues.

Note that this attack works even with Macro execution disabled.

This attack allows remote attackers to modify files / execute code
as the user opening the document.

- CVE-2006-2199:

A security vulnerability related to OpenOffice.org documents
may allow certain Java applets to break through the 'sandbox'
and therefore have full access to system resources with current
user privileges. The offending Applets may be constructed to
destroy/replace system files, read or send private data, and/or
cause additional security issues.

Since Java applet support is only there for historical reasons,
as StarOffice was providing browser support, the support has now
been disabled by default.

- CVE-2006-3117:

A buffer overflow in the XML UTF8 converter allows for a value to
be written to an arbitrary location in memory. This may lead to
command execution in the context of the current user." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_40_openoffice.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the OpenOffice_org package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"OpenOffice_org-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-af-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-be-BY-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-bg-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ca-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cy-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-GB-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fi-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-galleries-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gu-IN-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hr-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hunspell-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-mono-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nb-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nn-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-officebean-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pa-IN-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-BR-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-vi-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-xh-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zu-2.0.0-1.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-1.1.1-23.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ca-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fi-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-1.1.3-16.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ca-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fi-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-2.0.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
