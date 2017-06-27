#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2605 and 
# CentOS Errata and Security Advisory 2016:2605 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95351);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2016-5011");
  script_osvdb_id(141270);
  script_xref(name:"RHSA", value:"2016:2605");

  script_name(english:"CentOS 7 : util-linux (CESA-2016:2605)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for util-linux is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The util-linux packages contain a large variety of low-level system
utilities that are necessary for a Linux system to function. Among
others, these include the fdisk configuration tool and the login
program.

Security Fix(es) :

* It was found that util-linux's libblkid library did not properly
handle Extended Boot Record (EBR) partitions when reading MS-DOS
partition tables. An attacker with physical USB access to a protected
machine could insert a storage device with a specially crafted
partition table that could, for example, trigger an infinite loop in
systemd-udevd, resulting in a denial of service on that machine.
(CVE-2016-5011)

Red Hat would like to thank Michael Gruhn for reporting this issue.
Upstream acknowledges Christian Moch as the original reporter.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003549.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e56eaa09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libblkid-2.23.2-33.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libblkid-devel-2.23.2-33.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmount-2.23.2-33.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmount-devel-2.23.2-33.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libuuid-2.23.2-33.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libuuid-devel-2.23.2-33.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"util-linux-2.23.2-33.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"uuidd-2.23.2-33.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
