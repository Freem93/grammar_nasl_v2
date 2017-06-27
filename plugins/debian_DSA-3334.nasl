#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3334. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85357);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/08/26 13:32:36 $");

  script_cve_id("CVE-2015-6251");
  script_osvdb_id(125878);
  script_xref(name:"DSA", value:"3334");

  script_name(english:"Debian DSA-3334-1 : gnutls28 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kurt Roeckx discovered that decoding a specific certificate with very
long DistinguishedName (DN) entries leads to double free. A remote
attacker can take advantage of this flaw by creating a specially
crafted certificate that, when processed by an application compiled
against GnuTLS, could cause the application to crash resulting in a
denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=795068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gnutls28"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3334"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnutls28 packages.

For the stable distribution (jessie), this problem has been fixed in
version 3.3.8-6+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls28");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
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
if (deb_check(release:"8.0", prefix:"gnutls-bin", reference:"3.3.8-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gnutls-doc", reference:"3.3.8-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"guile-gnutls", reference:"3.3.8-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls-deb0-28", reference:"3.3.8-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls-openssl27", reference:"3.3.8-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls28-dbg", reference:"3.3.8-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls28-dev", reference:"3.3.8-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutlsxx28", reference:"3.3.8-6+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
