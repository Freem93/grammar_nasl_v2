#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-594-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92953);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-6515");
  script_osvdb_id(142342);

  script_name(english:"Debian DLA-594-1 : openssh security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSH secure shell client and server had a denial of service
vulnerability reported.

CVE-2016-6515 The password authentication function in sshd in OpenSSH
before 7.3 does not limit password lengths for password
authentication, which allows remote attackers to cause a denial of
service (crypt CPU consumption) via a long string.

For Debian 7 'Wheezy', this problems has been fixed in version
6.0p1-4+deb7u6.

We recommend that you upgrade your openssh packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssh"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/15");
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
if (deb_check(release:"7.0", prefix:"openssh-client", reference:"6.0p1-4+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-client-udeb", reference:"6.0p1-4+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-server", reference:"6.0p1-4+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-server-udeb", reference:"6.0p1-4+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ssh", reference:"6.0p1-4+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ssh-askpass-gnome", reference:"6.0p1-4+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ssh-krb5", reference:"6.0p1-4+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
