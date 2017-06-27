#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-b7e8e980ef.
#

include("compat.inc");

if (description)
{
  script_id(94854);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2016-7545");
  script_xref(name:"FEDORA", value:"2016-b7e8e980ef");

  script_name(english:"Fedora 25 : checkpolicy / libselinux / libsemanage / libsepol / policycoreutils / etc (2016-b7e8e980ef)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update backports several fixes from upstream and also fixes
sandbox issues including CVE-2016-7545

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-b7e8e980ef"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:checkpolicy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libselinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libsemanage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libsepol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:secilc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"checkpolicy-2.5-8.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"libselinux-2.5-12.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"libsemanage-2.5-8.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"libsepol-2.5-10.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"policycoreutils-2.5-17.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"secilc-2.5-6.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "checkpolicy / libselinux / libsemanage / libsepol / policycoreutils / etc");
}
