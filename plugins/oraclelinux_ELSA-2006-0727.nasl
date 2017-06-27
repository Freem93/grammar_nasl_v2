#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0727 and 
# Oracle Linux Security Advisory ELSA-2006-0727 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67419);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2005-3011", "CVE-2006-4810");
  script_bugtraq_id(14854, 20959);
  script_osvdb_id(30245, 30246);
  script_xref(name:"RHSA", value:"2006:0727");

  script_name(english:"Oracle Linux 3 / 4 : texinfo (ELSA-2006-0727)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0727 :

New Texinfo packages that fix various security vulnerabilities are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Texinfo is a documentation system that can produce both online
information and printed output from a single source file.

A buffer overflow flaw was found in Texinfo's texindex command. An
attacker could construct a carefully crafted Texinfo file that could
cause texindex to crash or possibly execute arbitrary code when
opened. (CVE-2006-4810)

A flaw was found in the way Texinfo's texindex command creates
temporary files. A local user could leverage this flaw to overwrite
files the user executing texindex has write access to. (CVE-2005-3011)

Users of Texinfo should upgrade to these updated packages which
contain backported patches and are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000090.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected texinfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"info-4.5-3.el3.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"info-4.5-3.el3.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"texinfo-4.5-3.el3.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"texinfo-4.5-3.el3.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"info-4.7-5.el4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"info-4.7-5.el4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"texinfo-4.7-5.el4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"texinfo-4.7-5.el4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "info / texinfo");
}
