#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-106-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82090);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-7273", "CVE-2014-7274", "CVE-2014-7275");
  script_bugtraq_id(70280, 70281, 70282);

  script_name(english:"Debian DLA-106-1 : getmail4 security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in getmail4, a mail
retriever with support for POP3, IMAP4 and SDPS, that could allow
man-in-the-middle attacks.

CVE-2014-7273

The IMAP-over-SSL implementation in getmail 4.0.0 through 4.43.0 does
not verify X.509 certificates from SSL servers, which allows
man-in-the-middle attackers to spoof IMAP servers and obtain sensitive
information via a crafted certificate.

CVE-2014-7274

The IMAP-over-SSL implementation in getmail 4.44.0 does not verify
that the server hostname matches a domain name in the subject's Common
Name (CN) field of the X.509 certificate, which allows
man-in-the-middle attackers to spoof IMAP servers and obtain sensitive
information via a crafted certificate from a recognized Certification
Authority.

CVE-2014-7275

The POP3-over-SSL implementation in getmail 4.0.0 through 4.44.0 does
not verify X.509 certificates from SSL servers, which allows
man-in-the-middle attackers to spoof POP3 servers and obtain sensitive
information via a crafted certificate.

For the squeeze distribution, those problems have been fixed by
importing a new upstream version: 4.46.0-1~deb6u1. The updated package
has been prepared by Osamu Aoki.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/12/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/getmail4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected getmail4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:getmail4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"getmail4", reference:"4.46.0-1~deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
