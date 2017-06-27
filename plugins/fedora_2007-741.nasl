#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-741.
#

include("compat.inc");

if (description)
{
  script_id(28232);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:04:03 $");

  script_cve_id("CVE-2007-5707", "CVE-2007-5708");
  script_xref(name:"FEDORA", value:"2007-741");

  script_name(english:"Fedora Core 6 : openldap-2.3.30-3.fc6 (2007-741)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Nov 2 2007 Jan Safranek <jsafranek at redhat.com>
    2.3.30-3.fc6

    - add ldconfig to devel post/postun (bz#240253)

    - do not create script in /tmp on startup (bz#188298)

    - start slupd for each replicated database (bz#210155)

    - fix security issues #359851 and #359861

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d5f8a0b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"compat-openldap-2.3.30_2.2.29-3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openldap-2.3.30-3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openldap-clients-2.3.30-3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openldap-debuginfo-2.3.30-3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openldap-devel-2.3.30-3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openldap-servers-2.3.30-3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"openldap-servers-sql-2.3.30-3.fc6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-debuginfo / etc");
}
