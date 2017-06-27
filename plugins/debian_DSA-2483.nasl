#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2483. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59761);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-2388");
  script_osvdb_id(82587);
  script_xref(name:"DSA", value:"2483");

  script_name(english:"Debian DSA-2483-1 : strongswan - authentication bypass");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An authentication bypass issue was discovered by the Codenomicon CROSS
project in strongSwan, an IPsec-based VPN solution. When using
RSA-based setups, a missing check in the gmp plugin could allow an
attacker presenting a forged signature to successfully authenticate
against a strongSwan responder.

The default configuration in Debian does not use the gmp plugin for
RSA operations but rather the OpenSSL plugin, so the packages as
shipped by Debian are not vulnerable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2483"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.4.1-5.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libstrongswan", reference:"4.4.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan", reference:"4.4.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-dbg", reference:"4.4.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev1", reference:"4.4.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev2", reference:"4.4.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-nm", reference:"4.4.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-starter", reference:"4.4.1-5.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
