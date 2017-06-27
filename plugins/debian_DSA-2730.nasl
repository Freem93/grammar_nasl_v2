#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2730. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69108);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-4242");
  script_bugtraq_id(61464);
  script_osvdb_id(95657);
  script_xref(name:"DSA", value:"2730");

  script_name(english:"Debian DSA-2730-1 : gnupg - information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Yarom and Falkner discovered that RSA secret keys could be leaked via
a side channel attack, where a malicious local user could obtain
private key information from another user on the system.

This update fixes this issue for the 1.4 series of GnuPG. GnuPG 2.x is
affected through its use of the libgcrypt11 library, a fix for which
will be published in DSA 2731."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=717880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gnupg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gnupg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2730"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnupg packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.4.10-4+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4.12-7+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg");
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
if (deb_check(release:"6.0", prefix:"gnupg", reference:"1.4.10-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg-curl", reference:"1.4.10-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg-udeb", reference:"1.4.10-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gpgv", reference:"1.4.10-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gpgv-udeb", reference:"1.4.10-4+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg", reference:"1.4.12-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-curl", reference:"1.4.12-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-udeb", reference:"1.4.12-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv", reference:"1.4.12-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-udeb", reference:"1.4.12-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-win32", reference:"1.4.12-7+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
