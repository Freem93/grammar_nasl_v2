#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-288-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85278);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-5600");
  script_osvdb_id(124938);

  script_name(english:"Debian DLA-288-2 : openssh regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In Debian LTS (squeeze), the fix for CVE-2015-5600[1] in openssh
1:5.5p1-6+squeeze7 breaks authentication mechanisms that rely on the
keyboard-interactive method. Thanks to Colin Watson for making aware
of that.

The patch fixing CVE-2015-5600 introduces the field 'devices_done' to
the KbdintAuthctxt struct, but does not initialize the field in the
kbdint_alloc() function. On Linux, this ends up filling that field
with junk data. The result of this are random login failures when
keyboard-interactive authentication is used.

This upload of openssh 1:5.5p1-6+squeeze7 to Debian LTS (squeeze) adds
that initialization of the `devices_done` field alongside the existing
initialization code.

People relying on keyboard-interactive based authentication mechanisms
with OpenSSH on Debian squeeze(-lts) systems are recommended to
upgrade OpenSSH to 1:5.5p1-6+squeeze7.

[1] https://lists.debian.org/debian-lts-announce/2015/08/msg00001.html

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/08/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/openssh"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/10");
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
if (deb_check(release:"6.0", prefix:"openssh-client", reference:"1:5.5p1-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openssh-client-udeb", reference:"1:5.5p1-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openssh-server", reference:"1:5.5p1-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openssh-server-udeb", reference:"1:5.5p1-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"ssh", reference:"1:5.5p1-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"ssh-askpass-gnome", reference:"1:5.5p1-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"ssh-krb5", reference:"1:5.5p1-6+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
