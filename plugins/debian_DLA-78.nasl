#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-78-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82223);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_cve_id("CVE-2014-3684");
  script_bugtraq_id(70242);

  script_name(english:"Debian DLA-78-1 : torque security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chad Vizino reported a vulnerability in torque, a PBS-derived batch
processing queueing system. A non-root user could exploit the flaw in
the tm_adopt() library call to kill any process, including root-owned
ones on any node in a job.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/10/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/torque"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorque2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtorque2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque-client-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque-mom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libtorque2", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libtorque2-dev", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"torque-client", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"torque-client-x11", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"torque-common", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"torque-mom", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"torque-pam", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"torque-scheduler", reference:"2.4.8+dfsg-9squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"torque-server", reference:"2.4.8+dfsg-9squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
