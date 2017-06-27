#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-380-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87729);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/01/05 15:06:29 $");

  script_name(english:"Debian DLA-380-1 : libvncserver security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue had been discovered and resolved by the libvncserver upstream
developer Karl Runge addressing thread-safety in libvncserver when
libvncserver is used for handling multiple VNC connections [1].

Unfortunately, it is not trivially feasible (because of ABI breakage)
to backport the related patch to libvncserver 0.9.7 as shipped in
Debian squeeze(-lts).

However, the thread-safety patch discussed resolved a related issue of
memory corruption caused by freeing global variables without
nullifying them when reusing them in another 'thread', especially
occurring when libvncserver is used for handling multiple VNC
connections

The described issue has been resolved with this version of
libvncserver and users of VNC are recommended to upgrade to this
version of the package.

[1]
https://github.com/LibVNC/libvncserver/commit/804335f9d296440bb708ca84
4f5d89b58b50b0c6

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://github.com/LibVNC/libvncserver/commit/804335f9d296440bb708ca844f5d89b58b50b0c6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b268757e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/01/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libvncserver"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linuxvnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/05");
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
if (deb_check(release:"6.0", prefix:"libvncserver-dev", reference:"0.9.7-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libvncserver0", reference:"0.9.7-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libvncserver0-dbg", reference:"0.9.7-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"linuxvnc", reference:"0.9.7-2+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
