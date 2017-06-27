#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93024);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6608", "CVE-2016-6609", "CVE-2016-6610", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613", "CVE-2016-6614", "CVE-2016-6615", "CVE-2016-6616", "CVE-2016-6617", "CVE-2016-6618", "CVE-2016-6619", "CVE-2016-6620", "CVE-2016-6622", "CVE-2016-6623", "CVE-2016-6624", "CVE-2016-6625", "CVE-2016-6626", "CVE-2016-6627", "CVE-2016-6628", "CVE-2016-6629", "CVE-2016-6630", "CVE-2016-6631", "CVE-2016-6632", "CVE-2016-6633");

  script_name(english:"FreeBSD : phpmyadmin -- multiple vulnerabilities (ef70b201-645d-11e6-9cdc-6805ca0b3d42)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The phpmyadmin development team reports : Summary Weakness with cookie
encryption Description A pair of vulnerabilities were found affecting
the way cookies are stored.

- The decryption of the username/password is vulnerable to a padding
oracle attack. The can allow an attacker who has access to a user's
browser cookie file to decrypt the username and password.

- A vulnerability was found where the same initialization vector (IV)
is used to hash the username and password stored in the phpMyAdmin
cookie. If a user has the same password as their username, an attacker
who examines the browser cookie can see that they are the but the
attacker can not directly decode these values from the cookie as it is
still hashed. Severity We consider this to be critical. Summary
Multiple XSS vulnerabilities Description Multiple vulnerabilities have
been discovered in the following areas of phpMyAdmin :

- Zoom search: Specially crafted column content can be used to trigger
an XSS attack

- GIS editor: Certain fields in the graphical GIS editor at not
properly escaped and can be used to trigger an XSS attack

- Relation view

- The following Transformations :

- Formatted

- Imagelink

- JPEG: Upload

- RegexValidation

- JPEG inline

- PNG inline

- transformation wrapper

- XML export

- MediaWiki export

- Designer

- When the MySQL server is running with a specially crafted log_bin
directive

- Database tab

- Replication feature

- Database search Severity We consider these vulnerabilities to be of
moderate severity. Summary Multiple XSS vulnerabilities Description
XSS vulnerabilities were discovered in :

- The database privilege check

- The 'Remove partitioning' functionality

Specially crafted database names can trigger the XSS attack. Severity
We consider these vulnerabilities to be of moderate severity. Summary
PHP code injection Description A vulnerability was found where a
specially crafted database name could be used to run arbitrary PHP
commands through the array export feature Severity We consider these
vulnerabilities to be of moderate severity. Summary Full path
disclosure Description A full path disclosure vulnerability was
discovered where a user can trigger a particular error in the export
mechanism to discover the full path of phpMyAdmin on the disk.
Severity We consider this vulnerability to be non-critical. Summary
SQL injection attack Description A vulnerability was reported where a
specially crafted database and/or table name can be used to trigger an
SQL injection attack through the export functionality. Severity We
consider this vulnerability to be serious Summary Local file exposure
Description A vulnerability was discovered where a user can exploit
the LOAD LOCAL INFILE functionality to expose files on the server to
the database system. Severity We consider this vulnerability to be
serious. Summary Local file exposure through symlinks with UploadDir
Description A vulnerability was found where a user can specially craft
a symlink on disk, to a file which phpMyAdmin is permitted to read but
the user is not, which phpMyAdmin will then expose to the user.
Severity We consider this vulnerability to be serious, however due to
the mitigation factors the default state is not vulnerable. Mitigation
factor 1) The installation must be run with UploadDir configured (not
the default) 2) The user must be able to create a symlink in the
UploadDir 3) The user running the phpMyAdmin application must be able
to read the file Summary Path traversal with SaveDir and UploadDir
Description A vulnerability was reported with the %u username
replacement functionality of the SaveDir and UploadDir features. When
the username substitution is configured, a specially crafted user name
can be used to circumvent restrictions to traverse the file system.
Severity We consider this vulnerability to be serious, however due to
the mitigation factors the default state is not vulnerable. Mitigation
factor 1) A system must be configured with the %u username
replacement, such as `$cfg['SaveDir'] = 'SaveDir_%u';` 2) The user
must be able to create a specially crafted MySQL user, including the
`/.` sequence of characters, such as `/../../` Summary Multiple XSS
vulnerabilities Description Multiple XSS vulnerabilities were found in
the following areas :

- Navigation pane and database/table hiding feature. A
specially crafted database name can be used to trigger an XSS attack.

- The 'Tracking' feature. A specially crafted query can be used to
trigger an XSS attack.

- GIS visualization feature. Severity We consider this vulnerability
to be non-critical. Summary SQL injection attack Description A
vulnerability was discovered in the following features where a user
can execute a SQL injection attack against the account of the control
user : User group Designer Severity We consider this vulnerability to
be serious. Mitigation factor The server must have a control user
account created in MySQL and configured in phpMyAdmin; installations
without a control user are not vulnerable. Summary SQL injection
attack Description A vulnerability was reported where a specially
crafted database and/or table name can be used to trigger a SQL
injection attack through the export functionality. Severity We
consider this vulnerability to be serious Summary Denial of service
(DOS) attack in transformation feature Description A vulnerability was
found in the transformation feature allowing a user to trigger a
denial-of-service (DOS) attack against the server. Severity We
consider this vulnerability to be non-critical Summary SQL injection
attack as control user Description A vulnerability was discovered in
the user interface preference feature where a user can execute a SQL
injection attack against the account of the control user. Severity We
consider this vulnerability to be serious. Mitigation factor The
server must have a control user account created in MySQL and
configured in phpMyAdmin; installations without a control user are not
vulnerable. Summary Unvalidated data passed to unserialize()
Description A vulnerability was reported where some data is passed to
the PHP unserialize() function without verification that it's valid
serialized data.

Due to how the PHP function operates,

Unserialization can result in code being loaded and executed due to
object instantiation and autoloading, and a malicious user may be able
to exploit this.

Therefore, a malicious user may be able to manipulate the stored data
in a way to exploit this weakness. Severity We consider this
vulnerability to be moderately severe. Summary DOS attack with forced
persistent connections Description A vulnerability was discovered
where an unauthenticated user is able to execute a denial-of-service
(DOS) attack by forcing persistent connections when phpMyAdmin is
running with $cfg['AllowArbitraryServer']=true;. Severity We consider
this vulnerability to be critical, although note that phpMyAdmin is
not vulnerable by default. Summary Denial of service (DOS) attack by
for loops Description A vulnerability has been reported where a
malicious authorized user can cause a denial-of-service (DOS) attack
on a server by passing large values to a loop. Severity We consider
this issue to be of moderate severity. Summary IPv6 and proxy server
IP-based authentication rule circumvention Description A vulnerability
was discovered where, under certain circumstances, it may be possible
to circumvent the phpMyAdmin IP-based authentication rules.

When phpMyAdmin is used with IPv6 in a proxy server environment, and
the proxy server is in the allowed range but the attacking computer is
not allowed, this vulnerability can allow the attacking computer to
connect despite the IP rules. Severity We consider this vulnerability
to be serious Mitigation factor * The phpMyAdmin installation must be
running with IP-based allow/deny rules * The phpMyAdmin installation
must be running behind a proxy server (or proxy servers) where the
proxy server is 'allowed' and the attacker is 'denied' * The
connection between the proxy server and phpMyAdmin must be via IPv6
Summary Detect if user is logged in Description A vulnerability was
reported where an attacker can determine whether a user is logged in
to phpMyAdmin.

The user's session, username, and password are not compromised by this
vulnerability. Severity We consider this vulnerability to be
non-critical. Summary Bypass URL redirect protection Description A
vulnerability was discovered where an attacker could redirect a user
to a malicious web page. Severity We consider this to be of moderate
severity Summary Referrer leak in url.php Description A vulnerability
was discovered where an attacker can determine the phpMyAdmin host
location through the file url.php. Severity We consider this to be of
moderate severity. Summary Reflected File Download attack Description
A vulnerability was discovered where an attacker may be able to
trigger a user to download a specially crafted malicious SVG file.
Severity We consider this issue to be of moderate severity. Summary
ArbitraryServerRegexp bypass Description A vulnerability was reported
with the $cfg['ArbitraryServerRegexp'] configuration directive. An
attacker could reuse certain cookie values in a way of bypassing the
servers defined by ArbitraryServerRegexp. Severity We consider this
vulnerability to be critical. Mitigation factor Only servers using
`$cfg['ArbitraryServerRegexp']` are vulnerable to this attack. Summary
Denial of service (DOS) attack by changing password to a very long
string Description An authenticated user can trigger a
denial-of-service (DOS) attack by entering a very long password at the
change password dialog. Severity We consider this vulnerability to be
serious. Summary Remote code execution vulnerability when run as CGI
Description A vulnerability was discovered where a user can execute a
remote code execution attack against a server when phpMyAdmin is being
run as a CGI application. Under certain server configurations, a user
can pass a query string which is executed as a command-line argument
by the file generator_plugin.sh. Severity We consider this
vulnerability to be critical. Mitigation factor The file
`/libraries/plugins/transformations/generator_plugin.sh` may be
removed. Under certain server configurations, it may be sufficient to
remove execute permissions for this file. Summary Denial of service
(DOS) attack with dbase extension Description A flaw was discovered
where, under certain conditions, phpMyAdmin may not delete temporary
files during the import of ESRI files. Severity We consider this
vulnerability to be non-critical. Mitigation factor This vulnerability
only exists when PHP is running with the dbase extension, which is not
shipped by default, not available in most Linux distributions, and
doesn't compile with PHP7. Summary Remote code execution vulnerability
when PHP is running with dbase extension Description A vulnerability
was discovered where phpMyAdmin can be used to trigger a remote code
execution attack against certain PHP installations. Severity We
consider this vulnerability to be critical. Mitigation factor This
vulnerability only exists when PHP is running with the dbase
extension, which is not shipped by default, not available in most
Linux distributions, and doesn't compile with PHP7."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-29/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-30/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-31/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-32/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-33/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-34/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-35/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-36/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-37/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-38/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-39/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-40/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-41/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-42/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-43/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-45/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-46/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-47/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-48/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-49/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-50/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-51/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-52/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-53/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-54/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-55/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-56/"
  );
  # http://www.freebsd.org/ports/portaudit/ef70b201-645d-11e6-9cdc-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de3bd02a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"phpmyadmin>=4.6.0<4.6.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
