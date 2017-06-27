#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1524. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31630);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_osvdb_id(43341, 43342, 43343);
  script_xref(name:"DSA", value:"1524");

  script_name(english:"Debian DSA-1524-1 : krb5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the kdc
component of the krb5, a system for authenticating users and services
on a network. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2008-0062
    An unauthenticated remote attacker may cause a
    krb4-enabled KDC to crash, expose information, or
    execute arbitrary code. Successful exploitation of this
    vulnerability could compromise the Kerberos key database
    and host security on the KDC host.

  - CVE-2008-0063
    An unauthenticated remote attacker may cause a
    krb4-enabled KDC to expose information. It is
    theoretically possible for the exposed information to
    include secret key data on some platforms.

  - CVE-2008-0947
    An unauthenticated remote attacker can cause memory
    corruption in the kadmind process, which is likely to
    cause kadmind to crash, resulting in a denial of
    service. It is at least theoretically possible for such
    corruption to result in database corruption or arbitrary
    code execution, though we have no such exploit and are
    not aware of any such exploits in use in the wild. In
    versions of MIT Kerberos shipped by Debian, this bug can
    only be triggered in configurations that allow large
    numbers of open file descriptors in a process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1524"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the old stable distribution (sarge), these problems have been
fixed in version krb5 1.3.6-2sarge6.

For the stable distribution (etch), these problems have been fixed in
version 1.4.4-7etch5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/21");
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
if (deb_check(release:"3.1", prefix:"krb5-admin-server", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-clients", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-doc", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-ftpd", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-kdc", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-rsh-server", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-telnetd", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-user", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm55", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb5-dev", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb53", reference:"1.3.6-2sarge6")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-admin-server", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-clients", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-doc", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-ftpd", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-kdc", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-rsh-server", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-telnetd", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-user", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libkadm55", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dbg", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dev", reference:"1.4.4-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb53", reference:"1.4.4-7etch5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
