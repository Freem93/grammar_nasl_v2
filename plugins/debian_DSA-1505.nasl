#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1505. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31149);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/19 14:28:18 $");

  script_cve_id("CVE-2007-4571");
  script_bugtraq_id(25807);
  script_osvdb_id(39234);
  script_xref(name:"DSA", value:"1505");

  script_name(english:"Debian DSA-1505-1 : alsa-driver - kernel memory leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Takashi Iwai supplied a fix for a memory leak in the snd_page_alloc
module. Local users could exploit this issue to obtain sensitive
information from the kernel (CVE-2007-4571 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1505"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the alsa-driver and alsa-modules-i386 packages.

For the oldstable distribution (sarge), this problem has been fixed in
version 1.0.8-7sarge1. The prebuilt modules provided by
alsa-modules-i386 have been rebuilt to take advantage of this update,
and are available in version 1.0.8+2sarge2.

For the stable distribution (etch), this problem has been fixed in
version 1.0.13-5etch1. This issue was already fixed for the version of
ALSA provided by linux-2.6 in DSA 1479."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:alsa-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"alsa-base", reference:"1.0.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-headers", reference:"1.0.8-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4-386", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4-586tsc", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4-686", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4-686-smp", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4-k6", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4-k7", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4-k7-smp", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4.27-4-386", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4.27-4-586tsc", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4.27-4-686", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4.27-4-686-smp", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4.27-4-k6", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4.27-4-k7", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-modules-2.4.27-4-k7-smp", reference:"1.0.8+2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"alsa-source", reference:"1.0.8-7sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"alsa-base", reference:"1.0.13-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsa-source", reference:"1.0.13-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-sound-base", reference:"1.0.13-5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
