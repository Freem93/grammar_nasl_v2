#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2866. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72647);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2014-1959");
  script_osvdb_id(103309);
  script_xref(name:"DSA", value:"2866");

  script_name(english:"Debian DSA-2866-1 : gnutls26 - certificate verification flaw");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Suman Jana reported that GnuTLS, deviating from the documented
behavior, considers a version 1 intermediate certificate as a CA
certificate by default.

The oldstable distribution (squeeze) is not affected by this problem
as X.509 version 1 trusted CA certificates are not allowed by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gnutls26"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2866"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnutls26 packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.12.20-8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"gnutls-bin", reference:"2.12.20-8")) flag++;
if (deb_check(release:"7.0", prefix:"gnutls26-doc", reference:"2.12.20-8")) flag++;
if (deb_check(release:"7.0", prefix:"guile-gnutls", reference:"2.12.20-8")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls-dev", reference:"2.12.20-8")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls-openssl27", reference:"2.12.20-8")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls26", reference:"2.12.20-8")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutls26-dbg", reference:"2.12.20-8")) flag++;
if (deb_check(release:"7.0", prefix:"libgnutlsxx27", reference:"2.12.20-8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
