#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-316. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15153);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:07:15 $");

  script_cve_id("CVE-2003-0358", "CVE-2003-0359");
  script_bugtraq_id(6806, 7953);
  script_osvdb_id(12019, 12021);
  script_xref(name:"DSA", value:"316");

  script_name(english:"Debian DSA-316-1 : nethack - buffer overflow, incorrect permissions");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The nethack and slashem packages are vulnerable to a buffer overflow
exploited via a long '-s' command line option. This vulnerability
could be used by an attacker to gain gid 'games' on a system where
nethack is installed.

Additionally, some setgid binaries in the nethack package have
incorrect permissions, which could allow a user who gains gid 'games'
to replace these binaries, potentially causing other users to execute
malicious code when they run nethack.

Note that slashem does not contain the file permission problem
CAN-2003-0359."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-316"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) these problems have been fixed in
version 3.4.0-3.0woody3.

For the old stable distribution (potato) these problems have been
fixed in version 3.3.0-7potato1.

We recommend that you update your nethack package.

For the stable distribution (woody) these problems have been fixed in
version 0.0.6E4F8-4.0woody3.

For the old stable distribution (potato) these problems have been
fixed in version 0.0.5E7-3potato1.

We recommend that you update your slashem package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nethack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/09");
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
if (deb_check(release:"2.2", prefix:"nethack", reference:"3.3.0-7potato1")) flag++;
if (deb_check(release:"3.0", prefix:"nethack", reference:"3.4.0-3.0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"nethack-common", reference:"3.4.0-3.0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"nethack-gnome", reference:"3.4.0-3.0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"nethack-qt", reference:"3.4.0-3.0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"nethack-x11", reference:"3.4.0-3.0woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
