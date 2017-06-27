#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-0610.
#

include("compat.inc");

if (description)
{
  script_id(29985);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:04:03 $");

  script_cve_id("CVE-2008-0123");
  script_xref(name:"FEDORA", value:"2008-0610");

  script_name(english:"Fedora 8 : moodle-1.8.4-1.fc8 (2008-0610)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upgrade to 1.8.4, fix CVE-2008-0123. Added Tamil (Sri Lanka) support.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=428731"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-January/006862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e201115f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-de_du");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-fr_ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-mi_tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-mi_wwow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-no_gr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-pt_br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sr_cr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sr_cr_bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sr_lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-ta_lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-to");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-zh_cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle-zh_tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"moodle-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-af-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ar-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-be-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-bg-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-bs-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ca-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-cs-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-da-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-de-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-de_du-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-el-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-es-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-et-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-eu-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-fa-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-fi-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-fil-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-fr-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-fr_ca-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ga-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-gl-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-gu-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-he-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-hi-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-hr-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-hu-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-hy-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-id-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-is-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-it-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ja-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ka-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-km-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-kn-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ko-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-lo-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-lt-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-lv-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-mi_tn-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-mi_wwow-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-mk-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ml-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-mn-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ms-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-nl-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-nn-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-no-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-no_gr-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-pl-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-pt-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-pt_br-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ro-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ru-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-si-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sk-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sl-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sm-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-so-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sq-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sr_cr-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sr_cr_bo-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sr_lt-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-sv-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ta-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-ta_lk-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-th-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-tl-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-to-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-tr-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-uk-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-vi-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-zh_cn-1.8.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"moodle-zh_tw-1.8.4-1.fc8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle / moodle-af / moodle-ar / moodle-be / moodle-bg / moodle-bs / etc");
}
