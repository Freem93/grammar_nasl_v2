#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:046
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13814);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
 
 name["english"] = "SuSE-SA:2003:046: sane";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2003:046 (sane).


The sane (Scanner Access Now Easy) package provides access to scanners
either locally or remotely over the network.

Several bugs in sane were fixed to avoid remote denial-of-service
attacks. These attacks can even be executed if the remote attacker
is not allowed to access the sane server by not listing the attackers
IP in the file sane.conf.
Per default saned only accepts local requests.

As a temporary workaround saned can be started via xinetd or inetd in
conjunction with tcpwrapper to restrict remote access.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_046_sane.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the sane package";
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
if ( rpm_check( reference:"sane-1.0.5-295", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sane-1.0.7-217", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sane-1.0.8-143", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sane-", release:"SUSE7.3")
 || rpm_exists(rpm:"sane-", release:"SUSE8.0")
 || rpm_exists(rpm:"sane-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0773", value:TRUE);
 set_kb_item(name:"CVE-2003-0774", value:TRUE);
 set_kb_item(name:"CVE-2003-0775", value:TRUE);
 set_kb_item(name:"CVE-2003-0776", value:TRUE);
 set_kb_item(name:"CVE-2003-0777", value:TRUE);
 set_kb_item(name:"CVE-2003-0778", value:TRUE);
}
