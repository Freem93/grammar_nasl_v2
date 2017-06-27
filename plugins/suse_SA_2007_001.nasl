#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:001
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24456);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2007:001: OpenOffice_org";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:001 (OpenOffice_org).


Security problems were fixed in the WMF and Enhanced WMF handling
in OpenOffice_org These could potentially be used to execute code
or crash OpenOffice when a user could be convinced to open specially
crafted document (for instance a document sent by E-mail).

This issue is tracked by the Mitre CVE ID CVE-2006-5870.

openSUSE 10.2 is not affected by this problem, it already contains
the fixed OpenOffice_org 2.1 version.

Additionally the OpenOffice_org 2.0 version in SLED 10 was fitted with
hooks to add OfficeXML support with a later update.

Due to the very large size of this update and mirror lag it might
take some hours or days until the updates are available on our mirrors." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_01_openoffice.html" );
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
if ( rpm_check( reference:"OpenOffice_org-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-af-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-be-BY-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-bg-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ca-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cy-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-GB-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fi-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-galleries-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gu-IN-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hr-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hunspell-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-mono-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nb-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nn-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-officebean-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pa-IN-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-BR-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-vi-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-xh-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zu-2.0.0-1.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-ar-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-ca-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-cs-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-da-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-de-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-el-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-en-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-es-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-et-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-fi-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-fr-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-gnome-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-hu-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-it-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-ja-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-kde-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-ko-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-nl-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-pl-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-pt-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-ru-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-sk-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-sl-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-sv-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-tr-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-zh-CN-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org1-zh-TW-1.1.3-4.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
