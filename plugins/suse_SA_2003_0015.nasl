#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0015
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13779);
 script_bugtraq_id(6974);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0108");
 
 name["english"] = "SUSE-SA:2003:0015: tcpdump";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:0015 (tcpdump).


The network traffic analyzer tool tcpdump is vulnerable to a denial-of-
service condition while parsing ISAKMP or BGP packets. This bug can
be exploited remotely by an attacker to stop the use of tcpdump for
analyzing network traffic for signs of security breaches or alike.
Another bug may lead to system compromise due to the handling of
malformed NFS packets send by an attacker.
Please note, that tcpdump drops root privileges right after allocating
the needed raw sockets.

There is no temporary fix known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_015_tcpdump.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the tcpdump package";
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
if ( rpm_check( reference:"tcpdump-3.4a6-375", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.4a6-376", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-321", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-322", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.1-198", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"SUSE7.1")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE7.2")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE7.3")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE8.0")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0108", value:TRUE);
}
