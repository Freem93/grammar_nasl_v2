#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3613. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91924);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-5008");
  script_osvdb_id(140745);
  script_xref(name:"DSA", value:"3613");

  script_name(english:"Debian DSA-3613-1 : libvirt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vivian Zhang and Christoph Anton Mitterer discovered that setting an
empty VNC password does not work as documented in Libvirt, a
virtualisation abstraction library. When the password on a VNC server
is set to the empty string, authentication on the VNC server will be
disabled, allowing any user to connect, despite the documentation
declaring that setting an empty password for the VNC server prevents
all client connections. With this update the behaviour is enforced by
setting the password expiration to 'now'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3613"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the stable distribution (jessie), this problem has been fixed in
version 1.2.9-9+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");
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
if (deb_check(release:"8.0", prefix:"libvirt-bin", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-clients", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon-system", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-dev", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-doc", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-sanlock", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0", reference:"1.2.9-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0-dbg", reference:"1.2.9-9+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
