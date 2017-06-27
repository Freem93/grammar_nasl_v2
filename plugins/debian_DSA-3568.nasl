#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3568. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90927);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-4008");
  script_osvdb_id(136947);
  script_xref(name:"DSA", value:"3568");

  script_name(english:"Debian DSA-3568-1 : libtasn1-6 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Pascal Cuoq and Miod Vallat discovered that Libtasn1, a library to
manage ASN.1 structures, does not correctly handle certain malformed
DER certificates. A remote attacker can take advantage of this flaw to
cause an application using the Libtasn1 library to hang, resulting in
a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libtasn1-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3568"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtasn1-6 packages.

For the stable distribution (jessie), this problem has been fixed in
version 4.2-3+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtasn1-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libtasn1-3-bin", reference:"4.2-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6", reference:"4.2-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6-dbg", reference:"4.2-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6-dev", reference:"4.2-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-bin", reference:"4.2-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-doc", reference:"4.2-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
