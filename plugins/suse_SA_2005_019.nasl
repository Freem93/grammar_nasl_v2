#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:019
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17618);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 
 name["english"] = "SUSE-SA:2005:019: mysql";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:019 (mysql).


MySQL is an Open Source database server, commonly used together with
web services provided by PHP scripts or similar.

This security update fixes a broken mysqlhotcopy script as well as
several security related bugs:

- CVE-2005-0709: MySQL allowed remote authenticated users with
INSERT and DELETE privileges to execute arbitrary code by using
CREATE FUNCTION to access libc calls, as demonstrated by using strcat,
on_exit, and exit.

- CVE-2005-0710: MySQL allowed remote authenticated users with
INSERT and DELETE privileges to bypass library path restrictions
and execute arbitrary libraries by using INSERT INTO to modify the
mysql.func table, which is processed by the udf_init function.

- CVE-2005-0711: MySQL used predictable file names when creating
temporary tables, which allows local users with CREATE TEMPORARY
TABLE privileges to overwrite arbitrary files via a symlink attack.


The first two vulnerabilities can be exploited by an attacker using
SQL inject attack vectors into a flawed PHP application for instance." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_19_mysql.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/25");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the mysql package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mysql-3.23.55-32", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-Max-3.23.55-32", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-4.0.15-71", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-Max-4.0.15-71", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-4.0.18-32.13", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-Max-4.0.18-32.13", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-4.0.21-4.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-Max-4.0.21-4.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"mysql-", release:"SUSE8.2")
 || rpm_exists(rpm:"mysql-", release:"SUSE9.0")
 || rpm_exists(rpm:"mysql-", release:"SUSE9.1")
 || rpm_exists(rpm:"mysql-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0709", value:TRUE);
 set_kb_item(name:"CVE-2005-0710", value:TRUE);
 set_kb_item(name:"CVE-2005-0711", value:TRUE);
}
