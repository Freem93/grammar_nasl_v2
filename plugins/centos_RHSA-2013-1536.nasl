#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1536 and 
# CentOS Errata and Security Advisory 2013:1536 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79156);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/12 17:31:56 $");

  script_cve_id("CVE-2013-4419");
  script_bugtraq_id(63226);
  script_osvdb_id(98713);
  script_xref(name:"RHSA", value:"2013:1536");

  script_name(english:"CentOS 6 : libguestfs (CESA-2013:1536)");
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

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Libguestfs is a library and set of tools for accessing and modifying
guest disk images.

It was found that guestfish, which enables shell scripting and command
line access to libguestfs, insecurely created the temporary directory
used to store the network socket when started in server mode. A local
attacker could use this flaw to intercept and modify other user's
guestfish command, allowing them to perform arbitrary guestfish
actions with the privileges of a different user, or use this flaw to
obtain authentication credentials. (CVE-2013-4419)

This issue was discovered by Michael Scherer of the Red Hat Regional
IT team.

These updated libguestfs packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All libguestfs users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/000983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f558e4a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libguestfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
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
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-devel-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-java-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-java-devel-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-javadoc-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-tools-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-tools-c-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ocaml-libguestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"python-libguestfs-1.20.11-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ruby-libguestfs-1.20.11-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
