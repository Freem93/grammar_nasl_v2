#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2545. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62016);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-2652", "CVE-2012-3515");
  script_bugtraq_id(53725);
  script_osvdb_id(82452, 85196);
  script_xref(name:"DSA", value:"2545");

  script_name(english:"Debian DSA-2545-1 : qemu - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in QEMU, a fast
processor emulator. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2012-2652 :
    The snapshot mode of QEMU (-snapshot) incorrectly
    handles temporary files used to store the current state,
    making it vulnerable to symlink attacks (including
    arbitrary file overwriting and guest information
    disclosure) due to a race condition.

  - CVE-2012-3515 :
    QEMU does not properly handle VT100 escape sequences
    when emulating certain devices with a virtual console
    backend. An attacker within a guest with access to the
    vulnerable virtual console could overwrite memory of
    QEMU and escalate privileges to that of the qemu
    process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2545"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu packages.

For the stable distribution (squeeze), these problems have been fixed
in version 0.12.5+dfsg-3squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libqemu-dev", reference:"0.12.5+dfsg-3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"qemu", reference:"0.12.5+dfsg-3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"qemu-keymaps", reference:"0.12.5+dfsg-3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"qemu-system", reference:"0.12.5+dfsg-3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"qemu-user", reference:"0.12.5+dfsg-3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"qemu-user-static", reference:"0.12.5+dfsg-3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"qemu-utils", reference:"0.12.5+dfsg-3squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
