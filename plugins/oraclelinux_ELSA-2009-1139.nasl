#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1139 and 
# Oracle Linux Security Advisory ELSA-2009-1139 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67888);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2009-1889");
  script_bugtraq_id(35530);
  script_osvdb_id(55588);
  script_xref(name:"RHSA", value:"2009:1139");

  script_name(english:"Oracle Linux 4 : pidgin (ELSA-2009-1139)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1139 :

Updated pidgin packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously. The
AOL Open System for CommunicAtion in Realtime (OSCAR) protocol is used
by the AOL ICQ and AIM instant messaging systems.

A denial of service flaw was found in the Pidgin OSCAR protocol
implementation. If a remote ICQ user sent a web message to a local
Pidgin user using this protocol, it would cause excessive memory
usage, leading to a denial of service (Pidgin crash). (CVE-2009-1889)

These updated packages also fix the following bug :

* the Yahoo! Messenger Protocol changed, making it incompatible (and
unusable) with Pidgin versions prior to 2.5.7. This update provides
Pidgin 2.5.8, which implements version 16 of the Yahoo! Messenger
Protocol, which resolves this issue.

Note: These packages upgrade Pidgin to version 2.5.8. Refer to the
Pidgin release notes for a full list of changes:
http://developer.pidgin.im/wiki/ChangeLog

All Pidgin users should upgrade to these updated packages, which
correct these issues. Pidgin must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-July/001068.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"finch-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"finch-devel-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-devel-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-perl-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-tcl-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-devel-2.5.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-perl-2.5.8-1.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
