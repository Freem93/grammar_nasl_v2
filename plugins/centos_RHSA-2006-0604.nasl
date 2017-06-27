#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0604 and 
# CentOS Errata and Security Advisory 2006:0604 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22136);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-3694");
  script_bugtraq_id(18944);
  script_osvdb_id(27144);
  script_xref(name:"RHSA", value:"2006:0604");

  script_name(english:"CentOS 3 / 4 : ruby (CESA-2006:0604)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix security issues are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for object-oriented
programming.

A number of flaws were found in the safe-level restrictions in Ruby.
It was possible for an attacker to create a carefully crafted
malicious script that can allow the bypass of certain safe-level
restrictions. (CVE-2006-3694)

Users of Ruby should update to these erratum packages, which contain a
backported patch and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac1d0008"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afda3ce6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a56c2d2b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dc1bee4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013078.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52d8576f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2044411c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/11");
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
if (rpm_check(release:"CentOS-3", reference:"irb-1.6.8-9.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-1.6.8-9.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-devel-1.6.8-9.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-docs-1.6.8-9.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-libs-1.6.8-9.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-mode-1.6.8-9.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-tcltk-1.6.8-9.EL3.6")) flag++;

if (rpm_check(release:"CentOS-4", reference:"irb-1.8.1-7.EL4.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-1.8.1-7.EL4.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-devel-1.8.1-7.EL4.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-docs-1.8.1-7.EL4.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-libs-1.8.1-7.EL4.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-mode-1.8.1-7.EL4.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-tcltk-1.8.1-7.EL4.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
