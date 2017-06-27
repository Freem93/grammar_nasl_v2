#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0394. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63975);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 18:01:07 $");

  script_cve_id("CVE-2011-0720");
  script_osvdb_id(70753);
  script_xref(name:"RHSA", value:"2011:0394");

  script_name(english:"RHEL 5 : conga (RHSA-2011:0394)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated conga packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The conga packages provide a web-based administration tool for remote
cluster and storage management.

A privilege escalation flaw was found in luci, the Conga web-based
administration application. A remote attacker could possibly use this
flaw to obtain administrative access, allowing them to read, create,
or modify the content of the luci application. (CVE-2011-0720)

Users of Conga are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages, luci must be restarted ('service luci restart') for
the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0720.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0394.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected luci and / or ricci packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"luci-0.12.2-24.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"luci-0.12.2-24.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ricci-0.12.2-24.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ricci-0.12.2-24.el5_6.1")) flag++;

if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"luci-0.12.2-24.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"luci-0.12.2-24.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"ricci-0.12.2-24.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"ricci-0.12.2-24.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
