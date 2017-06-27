#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:018
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13788);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-0143");
 
 name["english"] = "SUSE-SA:2003:018: qpopper";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:018 (qpopper).


The Post-Office-Protocol- (POP-) Server qpopper (version 4) was
vulnerable to a buffer overflow. The buffer overflow occurs after
authentication has taken place. Therefore pop-users with a valid
account can execute arbitrary code on the system running qpopper.
Depending on the setup, the malicious code is run with higher privileges.

There is no temporary fix known, please update your system.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_018_qpopper.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the qpopper package";
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
if ( rpm_check( reference:"qpopper-4.0.4-133", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qpopper-4.0.3-178", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"qpopper-", release:"SUSE8.1")
 || rpm_exists(rpm:"qpopper-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2003-0143", value:TRUE);
}
