#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:047
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13815);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-0914");
 
 name["english"] = "SuSE-SA:2003:047: bind8";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2003:047 (bind8).


To resolve IP addresses to host and domain names and vice versa the
DNS service needs to be consulted. The most popular DNS software is
the BIND8 and BIND9 suite. The BIND8 code is vulnerable to a remote
denial-of-service attack by poisoning the cache with authoritative
negative responses that should not be accepted otherwise.
To execute this attack a name-server needs to be under malicious
control and the victim's bind8 has to query this name-server.
The attacker can set a high TTL value to keep his negative record as
long as possible in the cache of the victim. For this time the clients
of the attacked site that rely on the bind8 service will not be able
to reach the domain specified in the negative record.
These records should disappear after the time-interval (TTL) elapsed.

There is no temporary workaround for this bug.

To make this update effective run 'rcnamed restart' as root please.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_47_bind8.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the bind8 package";
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
if ( rpm_check( reference:"bind8-8.2.4-334", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-334", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-336", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.3.4-64", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"bind8-", release:"SUSE7.3")
 || rpm_exists(rpm:"bind8-", release:"SUSE8.0")
 || rpm_exists(rpm:"bind8-", release:"SUSE8.1")
 || rpm_exists(rpm:"bind8-", release:"SUSE8.2") )
{
 set_kb_item(name:"CVE-2003-0914", value:TRUE);
}
