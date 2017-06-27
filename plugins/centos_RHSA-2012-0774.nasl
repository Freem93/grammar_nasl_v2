#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0774 and 
# CentOS Errata and Security Advisory 2012:0774 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59919);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/28 23:58:55 $");

  script_cve_id("CVE-2012-2690");
  script_bugtraq_id(53932);
  script_osvdb_id(82898);
  script_xref(name:"RHSA", value:"2012:0774");

  script_name(english:"CentOS 6 : libguestfs (CESA-2012:0774)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libguestfs packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

libguestfs is a library for accessing and modifying guest disk images.

It was found that editing files with virt-edit left said files in a
world-readable state (and did not preserve the file owner or
Security-Enhanced Linux context). If an administrator on the host used
virt-edit to edit a file inside a guest, the file would be left with
world-readable permissions. This could lead to unprivileged guest
users accessing files they would otherwise be unable to.
(CVE-2012-2690)

These updated libguestfs packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.3
Technical Notes for information on the most significant of these
changes.

Users of libguestfs are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018710.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ef54283"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libguestfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-java-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-java-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-javadoc-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-tools-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-tools-c-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ocaml-libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"python-libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ruby-libguestfs-1.16.19-1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
