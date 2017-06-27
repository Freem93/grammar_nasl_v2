#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-243. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15080);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:02:53 $");

  script_cve_id("CVE-2002-1393");
  script_xref(name:"DSA", value:"243");

  script_name(english:"Debian DSA-243-1 : kdemultimedia - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The KDE team discovered several vulnerabilities in the K Desktop
Environment. In some instances KDE fails to properly quote parameters
of instructions passed to a command shell for execution. These
parameters may incorporate data such as URLs, filenames and e-mail
addresses, and this data may be provided remotely to a victim in an
e-mail, a webpage or files on a network filesystem or other untrusted
source.

By carefully crafting such data an attacker might be able to execute
arbitrary commands on a vulnerable system using the victim's account
and privileges. The KDE Project is not aware of any existing exploits
of these vulnerabilities. The patches also provide better safe guards
and check data from untrusted sources more strictly in multiple
places."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20021220-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-243"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the KDE packages.

For the current stable distribution (woody), these problems have been
fixed in version 2.2.2-8.2. Please note that we are unable to provide
updated packages for both MIPS architectures since the compilation of
kdemultimedia triggers an internal compiler error on these machines.

The old stable distribution (potato) does not contain KDE packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"artsbuilder", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"kdemultimedia-dev", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"kmid", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"kmidi", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"kmix", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"kscd", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"libarts-mpeglib", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"mpeglib", reference:"2.2.2-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"noatun", reference:"2.2.2-8.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
