#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:040
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15726);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0882", "CVE-2004-0930");
 
 name["english"] = "SUSE-SA:2004:040: samba";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:040 (samba).


There is a problem in the Samba file sharing service daemon, which
allows a remote user to have the service consume lots of computing
power and potentially crash the service by querying special wildcarded
filenames.

This attack can be successful if the Samba daemon is running and a
remote user has access to a share (even read only).

The Samba team has issued the new Samba version 3.0.8 to fix this
problem, this update backports the relevant patch.

This issue has been assigned the Mitre CVE ID CVE-2004-0930.


Stefan Esser found a problem in the Unicode string handling in the
Samba file handling which could lead to a remote heap buffer
overflow and might allow remote attackers to inject code in the smbd
process.

This issue has been assigned the Mitre CVE ID CVE-2004-0882.


We provide updated packages for both these problems.

The Samba version 2 packages are not affected by this problem." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_40_samba.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/16");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the samba package";
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
if ( rpm_check( reference:"samba-3.0.4-1.34.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.7-5.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"SUSE9.1")
 || rpm_exists(rpm:"samba-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-0882", value:TRUE);
 set_kb_item(name:"CVE-2004-0930", value:TRUE);
}
