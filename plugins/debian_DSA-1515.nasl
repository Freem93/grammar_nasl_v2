#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1515. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31426);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2007-3377", "CVE-2007-3409", "CVE-2007-6341");
  script_xref(name:"DSA", value:"1515");

  script_name(english:"Debian DSA-1515-1 : libnet-dns-perl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in
libnet-dns-perl. The Common Vulnerabilities and Exposures project
identifies the following problems :

It was discovered that libnet-dns-perl generates very weak transaction
IDs when sending queries (CVE-2007-3377 ). This update switches
transaction ID generation to the Perl random generator, making
prediction attacks more difficult.

Compression loops in domain names resulted in an infinite loop in the
domain name expander written in Perl (CVE-2007-3409 ). The Debian
package uses an expander written in C by default, but this
vulnerability has been addressed nevertheless.

Decoding malformed A records could lead to a crash (via an uncaught
Perl exception) of certain applications using libnet-dns-perl
(CVE-2007-6341 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=457445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1515"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libnet-dns-perl package.

For the old stable distribution (sarge), these problems have been
fixed in version 0.48-1sarge1.

For the stable distribution (etch), these problems have been fixed in
version 0.59-1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnet-dns-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libnet-dns-perl", reference:"0.48-1sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"libnet-dns-perl", reference:"0.59-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
