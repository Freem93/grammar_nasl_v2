#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2037. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45559);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/12/22 14:20:00 $");

  script_cve_id("CVE-2010-0436");
  script_bugtraq_id(39467);
  script_osvdb_id(63814);
  script_xref(name:"DSA", value:"2037");

  script_name(english:"Debian DSA-2037-1 : kdm (kdebase) - race condition");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sebastian Krahmer discovered that a race condition in the KDE Desktop
Environment's KDM display manager, allow a local user to elevate
privileges to root."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2037"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdm package.

For the stable distribution (lenny), this problem has been fixed in
version 4:3.5.9.dfsg.1-6+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"kappfinder", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kate", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kcontrol", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-bin", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-bin-kde3", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-data", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-dbg", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-dev", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-doc", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-doc-html", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdebase-kio-plugins", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdeeject", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdepasswd", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdeprint", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdesktop", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdm", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kfind", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"khelpcenter", reference:"4:4.0.0.really.3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kicker", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"klipper", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kmenuedit", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"konqueror", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"konqueror-nsplugins", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"konsole", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kpager", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kpersonalizer", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ksmserver", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ksplash", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ksysguard", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ksysguardd", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ktip", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kwin", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkonq4", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkonq4-dev", reference:"4:3.5.9.dfsg.1-6+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
