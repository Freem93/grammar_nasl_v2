#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2789. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70733);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6075");
  script_osvdb_id(99253);
  script_xref(name:"DSA", value:"2789");

  script_name(english:"Debian DSA-2789-1 : strongswan - Denial of service and authorization bypass");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found in the ASN.1 parser of strongSwan, an
IKE daemon used to establish IPsec protected links.

By sending a crafted ID_DER_ASN1_DN ID payload to a vulnerable pluto
or charon daemon, a malicious remote user can provoke a denial of
service (daemon crash) or an authorization bypass (impersonating a
different user, potentially acquiring VPN permissions she doesn't
have)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 4.4.1-5.4.

For the stable distribution (wheezy), this problem has been fixed in
version 4.5.2-1.5+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libstrongswan", reference:"4.4.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan", reference:"4.4.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-dbg", reference:"4.4.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev1", reference:"4.4.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev2", reference:"4.4.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-nm", reference:"4.4.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-starter", reference:"4.4.1-5.4")) flag++;
if (deb_check(release:"7.0", prefix:"libstrongswan", reference:"4.5.2-1.5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan", reference:"4.5.2-1.5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-dbg", reference:"4.5.2-1.5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev1", reference:"4.5.2-1.5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev2", reference:"4.5.2-1.5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-nm", reference:"4.5.2-1.5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-starter", reference:"4.5.2-1.5+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
