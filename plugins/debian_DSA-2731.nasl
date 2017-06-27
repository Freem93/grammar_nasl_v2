#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2731. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69109);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-4242");
  script_bugtraq_id(61464);
  script_osvdb_id(95657);
  script_xref(name:"DSA", value:"2731");

  script_name(english:"Debian DSA-2731-1 : libgcrypt11 - information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Yarom and Falkner discovered that RSA secret keys in applications
using the libgcrypt11 library, for example GnuPG 2.x, could be leaked
via a side channel attack, where a malicious local user could obtain
private key information from another user on the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libgcrypt11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgcrypt11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2731"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgcrypt11 packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.4.5-2+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.5.0-5+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgcrypt11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libgcrypt11", reference:"1.4.5-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libgcrypt11-dbg", reference:"1.4.5-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libgcrypt11-dev", reference:"1.4.5-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libgcrypt11-doc", reference:"1.4.5-2+squeeze1")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11", reference:"1.5.0-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-dbg", reference:"1.5.0-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-dev", reference:"1.5.0-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-doc", reference:"1.5.0-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgcrypt11-udeb", reference:"1.5.0-5+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
