#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-039. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14876);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0169");
  script_bugtraq_id(2223);
  script_osvdb_id(1731);
  script_xref(name:"DSA", value:"039");

  script_name(english:"Debian DSA-039-1 : glibc");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of GNU libc that was distributed with Debian GNU/Linux 2.2
suffered from 2 security problems :

  - It was possible to use LD_PRELOAD to load libraries that
    are listed in /etc/ld.so.cache, even for suid programs.
    This could be used to create (and overwrite) files which
    a user should not be allowed to.
  - By using LD_PROFILE suid programs would write data to a
    file to /var/tmp, which was not done safely. Again, this
    could be used to create (and overwrite) files which a
    user should not have access to.

Both problems have been fixed in version 2.1.3-17 and we recommend
that you upgrade your glibc packages immediately.


Please note that a side-effect of this upgrade is that ldd will no
longer work on suid programs, unless you logged in as root."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-039"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected glibc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/21");
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
if (deb_check(release:"2.2", prefix:"glibc-doc", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"i18ndata", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-dbg", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-dev", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-pic", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-prof", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-dbg", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-dev", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-pic", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-prof", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"libnss1-compat", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"locales", reference:"2.1.3-17")) flag++;
if (deb_check(release:"2.2", prefix:"nscd", reference:"2.1.3-17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
