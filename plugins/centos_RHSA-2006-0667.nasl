#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0667 and 
# CentOS Errata and Security Advisory 2006:0667 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22422);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/28 18:05:36 $");

  script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");
  script_osvdb_id(29004, 29005, 29006, 29007, 29008);
  script_xref(name:"RHSA", value:"2006:0667");

  script_name(english:"CentOS 3 / 4 : gzip (CESA-2006:0667)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gzip packages that fix several security issues are now
available for Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gzip package contains the GNU gzip data compression program.

Tavis Ormandy of the Google Security Team discovered two denial of
service flaws in the way gzip expanded archive files. If a victim
expanded a specially crafted archive, it could cause the gzip
executable to hang or crash. (CVE-2006-4334, CVE-2006-4338)

Tavis Ormandy of the Google Security Team discovered several code
execution flaws in the way gzip expanded archive files. If a victim
expanded a specially crafted archive, it could cause the gzip
executable to crash or execute arbitrary code. (CVE-2006-4335,
CVE-2006-4336, CVE-2006-4337)

Users of gzip should upgrade to these updated packages, which contain
a backported patch and is not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8375529"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efcbf20a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81190ca1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48dab2a6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21ec4d32"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?952268c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gzip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"gzip-1.3.3-13.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gzip-1.3.3-16.rhel4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
