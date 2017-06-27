#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-3308.
#

include("compat.inc");

if (description)
{
  script_id(28306);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2007-4033", "CVE-2007-5393", "CVE-2007-5935", "CVE-2007-5936", "CVE-2007-5937");
  script_xref(name:"FEDORA", value:"2007-3308");

  script_name(english:"Fedora 8 : tetex-3.0-44.3.fc8 (2007-3308)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - fix t1lib flaw CVE-2007-4033 (#352271)

    - fix CVE-2007-4352 CVE-2007-5392 CVE-2007-5393, various
      xpdf flaws (#345121)

    - fix dvips -z buffer overflow with long href
      CVE-2007-5935 (#368591)

    - fix insecure usage of temporary file in dviljk
      CVE-2007-5936 CVE-2007-5937 (#368611, #368641)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=345121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=352271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=368591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=368611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=368641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=379861"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d9d3f58"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC8", reference:"tetex-3.0-44.3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"tetex-afm-3.0-44.3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"tetex-debuginfo-3.0-44.3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"tetex-doc-3.0-44.3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"tetex-dvips-3.0-44.3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"tetex-fonts-3.0-44.3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"tetex-latex-3.0-44.3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"tetex-xdvi-3.0-44.3.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-debuginfo / tetex-doc / tetex-dvips / etc");
}
