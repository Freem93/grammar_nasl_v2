#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-442-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89042);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/07/06 14:12:41 $");

  script_cve_id("CVE-2013-6441", "CVE-2015-1335");
  script_bugtraq_id(65562);
  script_osvdb_id(128213);

  script_name(english:"Debian DLA-442-1 : lxc security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brief introduction 

CVE-2013-6441

The template script lxc-sshd used to mount itself as /sbin/init in the
container using a writable bind-mount.

This update resolved the above issue by using a read-only
bind-mount instead preventing any form of potentially
accidental damage.

CVE-2015-1335

On container startup, lxc sets up the container's initial file system
tree by doing a bunch of mounting, guided by the container's
configuration file.

The container config is owned by the admin or user on the
host, so we do not try to guard against bad entries.
However, since the mount target is in the container, it's
possible that the container admin could divert the mount
with symbolic links. This could bypass proper container
startup (i.e. confinement of a root-owned container by the
restrictive apparmor policy, by diverting the required write
to /proc/self/attr/current), or bypass the (path-based)
apparmor policy by diverting, say, /proc to /mnt in the
container.

This update implements a safe_mount() function that prevents
lxc from doing mounts onto symbolic links.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/02/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/lxc"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected lxc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lxc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");
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
if (deb_check(release:"6.0", prefix:"lxc", reference:"0.7.2-1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
