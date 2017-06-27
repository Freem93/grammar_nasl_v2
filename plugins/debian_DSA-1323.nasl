#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1323. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25628);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");
  script_osvdb_id(36595, 36596, 36597);
  script_xref(name:"DSA", value:"1323");

  script_name(english:"Debian DSA-1323-1 : krb5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the MIT
reference implementation of the Kerberos network authentication
protocol suite, which may lead to the execution of arbitrary code. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-2442
    Wei Wang discovered that the free of an uninitialised
    pointer in the Kerberos RPC library may lead to the
    execution of arbitrary code.

  - CVE-2007-2443
    Wei Wang discovered that insufficient input sanitising
    in the Kerberos RPC library may lead to the execution of
    arbitrary code.

  - CVE-2007-2798
    It was discovered that a buffer overflow in the Kerberos
    administration daemon may lead to the execution of
    arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1323"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Kerberos packages.

For the old stable distribution (sarge) these problems have been fixed
in version 1.3.6-2sarge5. Packages for hppa, mips and powerpc are not
yet available. They will be provided later.

For the stable distribution (etch) these problems have been fixed in
version 1.4.4-7etch2. Packages for hppa and mips are not yet
available. They will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"krb5-admin-server", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-clients", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-doc", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-ftpd", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-kdc", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-rsh-server", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-telnetd", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-user", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm55", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb5-dev", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb53", reference:"1.3.6-2sarge5")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-admin-server", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-clients", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-doc", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-ftpd", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-kdc", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-rsh-server", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-telnetd", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-user", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libkadm55", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dbg", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dev", reference:"1.4.4-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb53", reference:"1.4.4-7etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
