#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1881. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44746);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2009-2632");
  script_osvdb_id(57843);
  script_xref(name:"DSA", value:"1881");

  script_name(english:"Debian DSA-1881-1 : cyrus-imapd-2.2 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the SIEVE component of cyrus-imapd, a highly
scalable enterprise mail system, is vulnerable to a buffer overflow
when processing SIEVE scripts. Due to incorrect use of the sizeof()
operator an attacker is able to pass a negative length to snprintf()
calls resulting in large positive values due to integer conversion.
This causes a buffer overflow which can be used to elevate privileges
to the cyrus system user. An attacker who is able to install SIEVE
scripts executed by the server is therefore able to read and modify
arbitrary email messages on the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1881"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-imapd-2.2 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.2.13-10+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 2.2.13-14+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-imapd-2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"cyrus-admin-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-clients-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-common-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-dev-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-doc-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-imapd-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-murder-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-nntpd-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"cyrus-pop3d-2.2", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcyrus-imap-perl22", reference:"2.2.13-10+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-admin-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-clients-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-common-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-dev-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-doc-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-imapd-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-murder-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-nntpd-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-pop3d-2.2", reference:"2.2.13-14+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libcyrus-imap-perl22", reference:"2.2.13-14+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
