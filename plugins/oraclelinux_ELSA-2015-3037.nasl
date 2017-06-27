#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-3037.
#

include("compat.inc");

if (description)
{
  script_id(83776);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/12/01 17:43:32 $");

  script_cve_id("CVE-2015-3627", "CVE-2015-3629", "CVE-2015-3630", "CVE-2015-3631");
  script_bugtraq_id(74558, 74559, 74563, 74566);

  script_name(english:"Oracle Linux 6 / 7 : docker (ELSA-2015-3037)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[1.6.1-1.0.1]
- Update source to 1.6.1 from 
https://github.com/docker/docker/releases/tag/v1.6.1
   Symlink traversal on container respawn allows local privilege 
escalation (CVE-2015-3629)
   Insecure opening of file-descriptor 1 leading to privilege escalation 
(CVE-2015-3627)
   Read/write proc paths allow host modification   information 
disclosure (CVE-2015-3630)
   Volume mounts allow LSM profile escalation (CVE-2015-3631)
   AppArmor policy improvements"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-May/005087.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-May/005088.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-1.6.1-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-devel-1.6.1-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-fish-completion-1.6.1-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-logrotate-1.6.1-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-pkg-devel-1.6.1-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-vim-1.6.1-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-zsh-completion-1.6.1-1.0.1.el6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-1.6.1-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-devel-1.6.1-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-fish-completion-1.6.1-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-logrotate-1.6.1-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-pkg-devel-1.6.1-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-vim-1.6.1-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-zsh-completion-1.6.1-1.0.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-devel / docker-fish-completion / docker-logrotate / etc");
}
