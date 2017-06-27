#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-268-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84551);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-0377", "CVE-2015-0418", "CVE-2015-3456");
  script_bugtraq_id(72194, 72219, 74640);
  script_osvdb_id(117338, 117344, 122072);

  script_name(english:"Debian DLA-268-1 : virtualbox-ose security update (Venom)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Three vulnerabilities have been fixed in the Debian squeeze-lts
version of VirtualBox (package name: virtualbox-ose), a x86
virtualisation solution.

CVE-2015-0377

Avoid VirtualBox allowing local users to affect availability via
unknown vectors related to Core, which might result in denial of
service. (Other issue than CVE-2015-0418).

CVE-2015-0418

Avoid VirtualBox allowing local users to affect availability via
unknown vectors related to Core, which might result in denial of
service. (Other issue than CVE-2015-0377).

CVE-2015-3456

The Floppy Disk Controller (FDC) in QEMU, also used in VirtualBox and
other virtualization products, allowed local guest users to cause a
denial of service (out-of-bounds write and guest crash) or possibly
execute arbitrary code via the (1) FD_CMD_READ_ID, (2)
FD_CMD_DRIVE_SPECIFICATION_COMMAND, or other unspecified commands, aka
VENOM.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/virtualbox-ose"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"virtualbox-ose", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-dbg", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-dkms", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-fuse", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-dkms", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-source", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-utils", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-x11", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-qt", reference:"3.2.10-dfsg-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-source", reference:"3.2.10-dfsg-1+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
