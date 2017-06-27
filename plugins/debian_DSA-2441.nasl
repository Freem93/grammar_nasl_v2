#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2441. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58460);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:37:37 $");

  script_cve_id("CVE-2012-1573");
  script_bugtraq_id(52667);
  script_osvdb_id(80259);
  script_xref(name:"DSA", value:"2441");

  script_name(english:"Debian DSA-2441-1 : gnutls26 - missing bounds check");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matthew Hall discovered that GNUTLS does not properly handle truncated
GenericBlockCipher structures nested inside TLS records, leading to
crashes in applications using the GNUTLS library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gnutls26"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2441"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnutls26 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.8.6-1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/26");
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
if (deb_check(release:"6.0", prefix:"gnutls-bin", reference:"2.8.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gnutls-doc", reference:"2.8.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"guile-gnutls", reference:"2.8.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgnutls-dev", reference:"2.8.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgnutls26", reference:"2.8.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libgnutls26-dbg", reference:"2.8.6-1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
