#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-602-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93199);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 14:30:00 $");

  script_cve_id("CVE-2016-6313");
  script_osvdb_id(143068);

  script_name(english:"Debian DLA-602-1 : gnupg security and hardening update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-6313

Felix Doerre and Vladimir Klebanov from the Karlsruhe Institute of
Technology discovered a flaw in the mixing functions of GnuPG's random
number generator. An attacker who obtains 4640 bits from the RNG can
trivially predict the next 160 bits of output.

A first analysis on the impact of this bug for GnuPG shows
that existing RSA keys are not weakened. For DSA and Elgamal
keys it is also unlikely that the private key can be
predicted from other public information.

Bypassing GnuPG key checking :

Weaknesses have been found in GnuPG signature validation that
attackers could exploit thanks to especially forged public keys and
under specific hardware-software conditions. While the underlying
problem cannot be solved only by software, GnuPG has been
strengthened, avoiding to rely on keyring signature caches when
verifying keys. Potential specific attacks are not valid any more with
the patch of GnuPG

Bypassing GnuPG key checking :

Vrije Universiteit Amsterdam and Katholieke Universteit Leuven
researchers discovered an attack method, known as Flip Feng Shui, that
concerns flaws in GnuPG. Researchers found that under specific
hardware-software conditions, attackers could bypass the GnuPG
signature validation by using forged public keys. While the underlying
problem cannot be solved only by software, GnuPG has been made more
robust to avoid relying on keyring signature caches when verifying
keys.

For Debian 7 'Wheezy', these issues have been addressed in version
1.4.12-7+deb7u8.

We recommend that you upgrade your gnupg packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gnupg"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpgv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpgv-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpgv-win32");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");
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
if (deb_check(release:"7.0", prefix:"gnupg", reference:"1.4.12-7+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-curl", reference:"1.4.12-7+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-udeb", reference:"1.4.12-7+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv", reference:"1.4.12-7+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-udeb", reference:"1.4.12-7+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-win32", reference:"1.4.12-7+deb7u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
