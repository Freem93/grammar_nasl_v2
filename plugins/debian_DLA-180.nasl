#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-180-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82166);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");
  script_bugtraq_id(73119, 73162, 73317);
  script_osvdb_id(118749, 119020, 119405);

  script_name(english:"Debian DLA-180-1 : gnutls26 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in GnuTLS, a library
implementing the TLS and SSL protocols. The Common Vulnerabilities and
Exposures project identifies the following problems :

CVE-2014-8155

Missing date/time checks on CA certificates

CVE-2015-0282

GnuTLS does not verify the RSA PKCS #1 signature algorithm to match
the signature algorithm in the certificate, leading to a potential
downgrade to a disallowed algorithm without detecting it.

CVE-2015-0294

GnuTLS does not check whether the two signature algorithms match on
certificate import.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/03/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/gnutls26"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:guile-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutls26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutls26-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"gnutls-bin", reference:"2.8.6-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"gnutls-doc", reference:"2.8.6-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"guile-gnutls", reference:"2.8.6-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libgnutls-dev", reference:"2.8.6-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libgnutls26", reference:"2.8.6-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libgnutls26-dbg", reference:"2.8.6-1+squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
