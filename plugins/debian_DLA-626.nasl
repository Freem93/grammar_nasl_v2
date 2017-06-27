#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-626-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93566);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6609", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613", "CVE-2016-6614", "CVE-2016-6620", "CVE-2016-6622", "CVE-2016-6623", "CVE-2016-6624", "CVE-2016-6630", "CVE-2016-6631");
  script_osvdb_id(143184, 143185, 143188, 143190, 143191, 143192, 143193, 143201, 143202, 143203, 143204, 143210, 143211);

  script_name(english:"Debian DLA-626-1 : phpmyadmin security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Phpmyadmin, a web administration tool for MySQL, had several
vulnerabilities reported.

CVE-2016-6606

A pair of vulnerabilities were found affecting the way cookies are
stored.

The decryption of the username/password is vulnerable to a
padding oracle attack. The can allow an attacker who has
access to a user's browser cookie file to decrypt the
username and password.

A vulnerability was found where the same initialization
vector is used to hash the username and password stored in
the phpMyAdmin cookie. If a user has the same password as
their username, an attacker who examines the browser cookie
can see that they are the same &mdash; but the attacker can
not directly decode these values from the cookie as it is
still hashed.

CVE-2016-6607

Cross site scripting vulnerability in the replication feature

CVE-2016-6609

A specially crafted database name could be used to run arbitrary PHP
commands through the array export feature.

CVE-2016-6611

A specially crafted database and/or table name can be used to trigger
a SQL injection attack through the SQL export functionality.

CVE-2016-6612

A user can exploit the LOAD LOCAL INFILE functionality to expose files
on the server to the database system.

CVE-2016-6613

A user can specially craft a symlink on disk, to a file which
phpMyAdmin is permitted to read but the user is not, which phpMyAdmin
will then expose to the user.

CVE-2016-6614

A vulnerability was reported with the %u username replacement
functionality of the SaveDir and UploadDir features. When the username
substitution is configured, a specially crafted user name can be used
to circumvent restrictions to traverse the file system.

CVE-2016-6620

A vulnerability was reported where some data is passed to the PHP
unserialize() function without verification that it's valid serialized
data. Due to how the PHP function operates, unserialization can result
in code being loaded and executed due to object instantiation and
autoloading, and a malicious user may be able to exploit this.
Therefore, a malicious user may be able to manipulate the stored data
in a way to exploit this weakness.

CVE-2016-6622

An unauthenticated user is able to execute a denial of service attack
by forcing persistent connections when phpMyAdmin is running with
$cfg['AllowArbitraryServer']=true;.

CVE-2016-6623

A malicious authorized user can cause a denial of service attack on a
server by passing large values to a loop.

CVE-2016-6624

A vulnerability was discovered where, under certain circumstances, it
may be possible to circumvent the phpMyAdmin IP-based authentication
rules. When phpMyAdmin is used with IPv6 in a proxy server
environment, and the proxy server is in the allowed range but the
attacking computer is not allowed, this vulnerability can allow the
attacking computer to connect despite the IP rules.

CVE-2016-6630

An authenticated user can trigger a denial of service attack by
entering a very long password at the change password dialog.

CVE-2016-6631

A vulnerability was discovered where a user can execute a remote code
execution attack against a server when phpMyAdmin is being run as a
CGI application. Under certain server configurations, a user can pass
a query string which is executed as a command-line argument by shell
scripts.

For Debian 7 'Wheezy', these problems have been fixed in version
3.4.11.1-2+deb7u6.

We recommend that you upgrade your phpmyadmin packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/phpmyadmin"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected phpmyadmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"phpmyadmin", reference:"3.4.11.1-2+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
