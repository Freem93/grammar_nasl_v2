#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:045
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13813);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-0886");
 
 name["english"] = "SuSE-SA:2003:045: hylafax";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2003:045 (hylafax).


Hylafax is an Open Source fax server which allows sharing of fax
equipment among computers by offering its service to clients by
a protocol similar to FTP.
The SuSE Security Team found a format bug condition during a code
review of the hfaxd server. It allows remote attackers to execute
arbitrary code as root. However, the bug can not be triggered in
hylafax' default configuration.

The 'capi4hylafax' packages also need to be updated as a dependency
where they are available.

After the update has been successfully applied the hfaxd server has
to be restarted by issuing the following command as root:

/etc/rc.d/hylafax restart

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_045_hylafax.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the hylafax package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"hylafax-4.1-303", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1-303", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.3-145", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"capi4hylafax-4.1.3-145", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.5-190", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"capi4hylafax-4.1.5-190", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.7-67", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"capi4hylafax-4.1.7-67", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"SUSE7.3")
 || rpm_exists(rpm:"hylafax-", release:"SUSE8.0")
 || rpm_exists(rpm:"hylafax-", release:"SUSE8.1")
 || rpm_exists(rpm:"hylafax-", release:"SUSE8.2")
 || rpm_exists(rpm:"hylafax-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2003-0886", value:TRUE);
}
