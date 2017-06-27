#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:799 and 
# CentOS Errata and Security Advisory 2005:799 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21860);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2337");
  script_bugtraq_id(14909);
  script_osvdb_id(19610);
  script_xref(name:"RHSA", value:"2005:799");

  script_name(english:"CentOS 3 / 4 : ruby (CESA-2005:799)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix an arbitrary command execution issue
are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 25 Oct 2005] Errata has been updated to include missing
packages for Red Hat Enterprise Linux 3.

Ruby is an interpreted scripting language for object-oriented
programming.

A bug was found in the way ruby handles eval statements. It is
possible for a malicious script to call eval in such a way that can
allow the bypass of certain safe-level restrictions. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2337 to this issue.

Users of Ruby should update to these erratum packages, which contain a
backported patch and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b29d580"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d34120eb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a8052bb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be18d095"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"irb-1.6.8-9.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"irb-1.6.8-9.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-1.6.8-9.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-devel-1.6.8-9.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-docs-1.6.8-9.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-libs-1.6.8-9.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-mode-1.6.8-9.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-tcltk-1.6.8-9.EL3.4")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-1.8.1-7.EL4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-devel-1.8.1-7.EL4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-docs-1.8.1-7.EL4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-libs-1.8.1-7.EL4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-mode-1.8.1-7.EL4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-tcltk-1.8.1-7.EL4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
