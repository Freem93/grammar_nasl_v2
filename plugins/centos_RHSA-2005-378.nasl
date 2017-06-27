#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:378 and 
# CentOS Errata and Security Advisory 2005:378 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21815);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1111");
  script_bugtraq_id(13159);
  script_xref(name:"RHSA", value:"2005:378");

  script_name(english:"CentOS 3 / 4 : cpio (CESA-2005:378)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cpio package that fixes multiple issues is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

GNU cpio copies files into or out of a cpio or tar archive.

A race condition bug was found in cpio. It is possible for a local
malicious user to modify the permissions of a local file if they have
write access to a directory in which a cpio archive is being
extracted. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1111 to this issue.

Additionally, this update adds cpio support for archives larger than
2GB. However, the size of individual files within an archive is
limited to 4GB.

All users of cpio are advised to upgrade to this updated package,
which contains backported fixes for these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011938.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d01eee5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011940.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af99d459"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011943.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ea4d933"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011944.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e805d3b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011951.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ab73095"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eef668a0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8a06d83"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?715ec650"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cpio package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cpio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-3", reference:"cpio-2.5-4.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cpio-2.5-8.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
