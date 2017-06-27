#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2151 and 
# CentOS Errata and Security Advisory 2015:2151 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87134);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2012-2150");
  script_osvdb_id(125255);
  script_xref(name:"RHSA", value:"2015:2151");

  script_name(english:"CentOS 7 : xfsprogs (CESA-2015:2151)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xfsprogs packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The xfsprogs packages contain a set of commands to use the XFS file
system, including the mkfs.xfs command to construct an XFS system.

It was discovered that the xfs_metadump tool of the xfsprogs suite did
not fully adhere to the standards of obfuscation described in its man
page. In case a user with the necessary privileges used xfs_metadump
and relied on the advertised obfuscation, the generated data could
contain unexpected traces of potentially sensitive information.
(CVE-2012-2150)

The xfsprogs packages have been upgraded to upstream version 3.2.2,
which provides a number of bug fixes and enhancements over the
previous version. This release also includes updates present in
upstream version 3.2.3, although it omits the mkfs.xfs default disk
format change (for metadata checksumming) which is present upstream.
(BZ#1223991)

Users of xfsprogs are advised to upgrade to these updated packages,
which fix these bugs and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002683.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f39c5479"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xfsprogs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xfsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xfsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xfsprogs-qa-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xfsprogs-3.2.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xfsprogs-devel-3.2.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xfsprogs-qa-devel-3.2.2-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
