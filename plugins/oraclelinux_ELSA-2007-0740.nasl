#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0740 and 
# Oracle Linux Security Advisory ELSA-2007-0740 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67554);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2007-2926");
  script_bugtraq_id(25037);
  script_osvdb_id(36235);
  script_xref(name:"RHSA", value:"2007:0740");

  script_name(english:"Oracle Linux 3 / 4 / 5 : bind (ELSA-2007-0740)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0740 :

Updated bind packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ISC BIND (Berkeley Internet Name Domain) is an implementation of the
DNS (Domain Name System) protocols.

A flaw was found in the way BIND generates outbound DNS query ids. If
an attacker is able to acquire a finite set of query IDs, it becomes
possible to accurately predict future query IDs. Future query ID
prediction may allow an attacker to conduct a DNS cache poisoning
attack, which can result in the DNS server returning incorrect client
query data. (CVE-2007-2926)

Users of BIND are advised to upgrade to these updated packages, which
contain backported patches to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000278.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000279.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000280.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-chroot-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-chroot-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-devel-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-devel-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-libs-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-libs-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"bind-utils-9.2.4-21.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"bind-utils-9.2.4-21.el3")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"bind-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"bind-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"bind-chroot-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"bind-chroot-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"bind-devel-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"bind-devel-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"bind-libs-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"bind-libs-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"bind-utils-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"bind-utils-9.2.4-27.0.1.el4")) flag++;

if (rpm_check(release:"EL5", reference:"bind-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"bind-chroot-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"bind-devel-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"bind-libbind-devel-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"bind-libs-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"bind-sdb-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"bind-utils-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"caching-nameserver-9.3.3-9.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
}
