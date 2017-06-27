#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0517 and 
# CentOS Errata and Security Advisory 2013:0517 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65149);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/11/12 17:08:53 $");

  script_cve_id("CVE-2013-0157");
  script_bugtraq_id(57168);
  script_xref(name:"RHSA", value:"2013:0517");

  script_name(english:"CentOS 6 : util-linux-ng (CESA-2013:0517)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated util-linux-ng packages that fix one security issue, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The util-linux-ng packages contain a large variety of low-level system
utilities that are necessary for a Linux operating system to function.

An information disclosure flaw was found in the way the mount command
reported errors. A local attacker could use this flaw to determine the
existence of files and directories they do not have access to.
(CVE-2013-0157)

These updated util-linux-ng packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of util-linux-ng are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2975ed3e"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cd55dd9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux-ng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libblkid-2.17.2-12.9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libblkid-devel-2.17.2-12.9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libuuid-2.17.2-12.9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libuuid-devel-2.17.2-12.9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"util-linux-ng-2.17.2-12.9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"uuidd-2.17.2-12.9.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
