#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2967. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76219);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2014-4617");
  script_bugtraq_id(68156);
  script_xref(name:"DSA", value:"2967");

  script_name(english:"Debian DSA-2967-1 : gnupg - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jean-Rene Reinhard, Olivier Levillain and Florian Maury reported that
GnuPG, the GNU Privacy Guard, did not properly parse certain garbled
compressed data packets. A remote attacker could use this flaw to
mount a denial of service against GnuPG by triggering an infinite
loop."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=752497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gnupg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2967"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnupg packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4.12-7+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"gnupg", reference:"1.4.12-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-curl", reference:"1.4.12-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-udeb", reference:"1.4.12-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv", reference:"1.4.12-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-udeb", reference:"1.4.12-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-win32", reference:"1.4.12-7+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
