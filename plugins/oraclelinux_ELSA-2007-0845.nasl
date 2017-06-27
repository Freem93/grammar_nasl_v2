#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0845 and 
# Oracle Linux Security Advisory ELSA-2007-0845 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67560);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:56 $");

  script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4065", "CVE-2007-4066");
  script_bugtraq_id(25082);
  script_osvdb_id(38675, 38676, 38677, 38678, 38679);
  script_xref(name:"RHSA", value:"2007:0845");

  script_name(english:"Oracle Linux 3 / 4 / 5 : libvorbis (ELSA-2007-0845)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0845 :

Updated libvorbis packages to correct several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libvorbis package contains runtime libraries for use in programs
that support Ogg Voribs. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

Several flaws were found in the way libvorbis processed audio data. An
attacker could create a carefully crafted OGG audio file in such a way
that it could cause an application linked with libvorbis to crash or
execute arbitrary code when it was opened. (CVE-2007-3106,
CVE-2007-4029, CVE-2007-4065, CVE-2007-4066)

Users of libvorbis are advised to upgrade to this updated package,
which contains backported patches that resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-September/000330.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-September/000333.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-September/000334.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvorbis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libvorbis-1.0-8.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libvorbis-1.0-8.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libvorbis-devel-1.0-8.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libvorbis-devel-1.0-8.el3")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"libvorbis-1.1.0-2.el4.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libvorbis-1.1.0-2.el4.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"libvorbis-devel-1.1.0-2.el4.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libvorbis-devel-1.1.0-2.el4.5")) flag++;

if (rpm_check(release:"EL5", reference:"libvorbis-1.1.2-3.el5.0")) flag++;
if (rpm_check(release:"EL5", reference:"libvorbis-devel-1.1.2-3.el5.0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvorbis / libvorbis-devel");
}
