#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2972 and 
# Oracle Linux Security Advisory ELSA-2016-2972 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95980);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2016-1248");
  script_osvdb_id(147697);
  script_xref(name:"RHSA", value:"2016:2972");

  script_name(english:"Oracle Linux 6 / 7 : vim (ELSA-2016-2972)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2972 :

An update for vim is now available for Red Hat Enterprise Linux 6 and
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Vim (Vi IMproved) is an updated and improved version of the vi editor.

Security Fix(es) :

* A vulnerability was found in vim in how certain modeline options
were treated. An attacker could craft a file that, when opened in vim
with modelines enabled, could execute arbitrary commands with
privileges of the user running vim. (CVE-2016-1248)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-December/006590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-December/006591.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

flag = 0;
if (rpm_check(release:"EL6", reference:"vim-X11-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"EL6", reference:"vim-common-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"EL6", reference:"vim-enhanced-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"EL6", reference:"vim-filesystem-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"EL6", reference:"vim-minimal-7.4.629-5.el6_8.1")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"vim-X11-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"vim-common-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"vim-enhanced-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"vim-filesystem-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"vim-minimal-7.4.160-1.el7_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-X11 / vim-common / vim-enhanced / vim-filesystem / vim-minimal");
}
