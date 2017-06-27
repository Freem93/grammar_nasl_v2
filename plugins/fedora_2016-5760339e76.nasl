#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-5760339e76.
#

include("compat.inc");

if (description)
{
  script_id(94808);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/15 14:40:19 $");

  script_cve_id("CVE-2016-6316", "CVE-2016-6317");
  script_xref(name:"FEDORA", value:"2016-5760339e76");

  script_name(english:"Fedora 25 : 1:rubygem-actionmailer / 1:rubygem-actionpack / etc (2016-5760339e76)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Rails 5.0.0.1.

Enable whole test suite in Railties.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-5760339e76"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC25", reference:"rubygem-actionmailer-5.0.0.1-1.fc25", epoch:"1")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-actionpack-5.0.0.1-2.fc25", epoch:"1")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-activerecord-5.0.0.1-1.fc25", epoch:"1")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-activesupport-5.0.0.1-1.fc25", epoch:"1")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-rails-5.0.0.1-1.fc25", epoch:"1")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-actioncable-5.0.0.1-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-actionview-5.0.0.1-2.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-activejob-5.0.0.1-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-activemodel-5.0.0.1-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"rubygem-railties-5.0.0.1-2.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:rubygem-actionmailer / 1:rubygem-actionpack / etc");
}
