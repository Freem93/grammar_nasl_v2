#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1578. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32379);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2007-3799", "CVE-2007-3806", "CVE-2007-3998", "CVE-2007-4657", "CVE-2008-2051");
  script_osvdb_id(36855);
  script_xref(name:"DSA", value:"1578");

  script_name(english:"Debian DSA-1578-1 : php4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in PHP version 4, a
server-side, HTML-embedded scripting language. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-3799
    The session_start function allows remote attackers to
    insert arbitrary attributes into the session cookie via
    special characters in a cookie that is obtained from
    various parameters.

  - CVE-2007-3806
    A denial of service was possible through a malicious
    script abusing the glob() function.

  - CVE-2007-3998
    Certain maliciously constructed input to the wordwrap()
    function could lead to a denial of service attack.

  - CVE-2007-4657
    Large len values of the stspn() or strcspn() functions
    could allow an attacker to trigger integer overflows to
    expose memory or cause denial of service.

  - CVE-2008-2051
    The escapeshellcmd API function could be attacked via
    incomplete multibyte chars."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1578"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php4 package.

For the stable distribution (etch), these problems have been fixed in
version 6:4.4.4-8+etch6.

The php4 packages are no longer present the unstable distribution
(sid)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-php4", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php4", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cgi", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cli", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-common", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-curl", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-dev", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-domxml", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-gd", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-imap", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-interbase", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-ldap", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcal", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcrypt", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mhash", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mysql", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-odbc", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pear", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pgsql", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pspell", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-recode", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-snmp", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-sybase", reference:"6:4.4.4-8+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"php4-xslt", reference:"6:4.4.4-8+etch6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
