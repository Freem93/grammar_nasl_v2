#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1321. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25615);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:41:27 $");

  script_cve_id("CVE-2007-3257");
  script_xref(name:"DSA", value:"1321");

  script_name(english:"Debian DSA-1321-1 : evolution-data-server - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the IMAP code in the Evolution Data Server
performs insufficient sanitising of a value later used an array index,
which can lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1321"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the evolution-data-server packages.

For the oldstable distribution (sarge) a different source package is
affected and will be fixed separately.

For the stable distribution (etch) this problem has been fixed in
version 1.6.3-5etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"evolution-data-server", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-data-server-common", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-data-server-dbg", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-data-server-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libcamel1.2-8", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libcamel1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libebook1.2-5", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libebook1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libecal1.2-6", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libecal1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-book1.2-2", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-book1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-cal1.2-5", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-cal1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserver1.2-7", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserver1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserverui1.2-6", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserverui1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libegroupwise1.2-10", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libegroupwise1.2-dev", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libexchange-storage1.2-1", reference:"1.6.3-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libexchange-storage1.2-dev", reference:"1.6.3-5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
