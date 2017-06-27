#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from CentOS
# Errata and Security Advisory 2014:0943.
#

include("compat.inc");

if (description)
{
  script_id(76840);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/26 23:39:25 $");

  script_name(english:"CentOS 7 : kexec-tools (CESA-2014:0943)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:"The remote CentOS host is missing a security update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-July/020448.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b9f580f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kexec-tools packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kexec-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kexec-tools-eppic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kexec-tools-2.0.4-32.el7.centos.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kexec-tools-eppic-2.0.4-32.el7.centos.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
