#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1196 and 
# CentOS Errata and Security Advisory 2011:1196 respectively.
#

include("compat.inc");

if (description)
{
  script_id(55996);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-2899");
  script_osvdb_id(74870);
  script_xref(name:"RHSA", value:"2011:1196");

  script_name(english:"CentOS 4 / 5 : system-config-printer (CESA-2011:1196)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated system-config-printer packages that fix one security issue are
now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

system-config-printer is a print queue configuration tool with a
graphical user interface.

It was found that system-config-printer did not properly sanitize
NetBIOS and workgroup names when searching for network printers. A
remote attacker could use this flaw to execute arbitrary code with the
privileges of the user running system-config-printer. (CVE-2011-2899)

All users of system-config-printer are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. Running instances of system-config-printer must be restarted
for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04195809"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017705.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7dade25"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e923399"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32ff6eae"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000212.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79bd80df"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ba2ac75"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected system-config-printer packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:system-config-printer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:system-config-printer-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:system-config-printer-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"system-config-printer-0.6.116.10-1.6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"system-config-printer-0.6.116.10-1.6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"system-config-printer-gui-0.6.116.10-1.6.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"system-config-printer-gui-0.6.116.10-1.6.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"system-config-printer-0.7.32.10-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"system-config-printer-libs-0.7.32.10-1.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
