#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:035
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13803);
 script_bugtraq_id(8485);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0688");
 
 name["english"] = "SUSE-SA:2003:035: sendmail";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:035 (sendmail).


The well known and widely used MTA sendmail is vulnerable to a
remote denial-of-service attack in version 8.12.8 and earlier (but not
before 8.12). The bug exists in the DNS map code. This feature is
enabled by specifying FEATURE(`enhdnsbl').
When sendmail receives an invalid DNS response it tries to call free(3)
on random data which results in a process crash.

After your system was updated you have to restart your sendmail daemon
to make the update effective.

There is no known workaround for this vulnerability other than using a
different MTA.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_035_sendmail.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the sendmail package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"sendmail-8.12.3-76", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-931", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-147", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-931", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.7-73", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-931", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"SUSE8.0")
 || rpm_exists(rpm:"sendmail-", release:"SUSE8.1")
 || rpm_exists(rpm:"sendmail-", release:"SUSE8.2") )
{
 set_kb_item(name:"CVE-2003-0688", value:TRUE);
}
