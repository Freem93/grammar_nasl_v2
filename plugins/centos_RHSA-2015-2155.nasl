#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2155 and 
# CentOS Errata and Security Advisory 2015:2155 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87137);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9652", "CVE-2014-9653");
  script_osvdb_id(79681, 104208, 107559, 107560, 108463, 108464, 108465, 108466, 108467, 113614, 115011, 115923, 115924, 118387);
  script_xref(name:"RHSA", value:"2015:2155");

  script_name(english:"CentOS 7 : file (CESA-2015:2155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated file packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The file command is used to identify a particular file according to
the type of data the file contains. It can identify many different
file types, including Executable and Linkable Format (ELF) binary
files, system libraries, RPM packages, and different graphics formats.

Multiple denial of service flaws were found in the way file parsed
certain Composite Document Format (CDF) files. A remote attacker could
use either of these flaws to crash file, or an application using file,
via a specially crafted CDF file. (CVE-2014-0207, CVE-2014-0237,
CVE-2014-0238, CVE-2014-3479, CVE-2014-3480, CVE-2014-3487,
CVE-2014-3587)

Two flaws were found in the way file processed certain Pascal strings.
A remote attacker could cause file to crash if it was used to identify
the type of the attacker-supplied file. (CVE-2014-3478, CVE-2014-9652)

Multiple flaws were found in the file regular expression rules for
detecting various files. A remote attacker could use these flaws to
cause file to consume an excessive amount of CPU. (CVE-2014-3538)

Multiple flaws were found in the way file parsed Executable and
Linkable Format (ELF) files. A remote attacker could use these flaws
to cause file to crash, disclose portions of its memory, or consume an
excessive amount of system resources. (CVE-2014-3710, CVE-2014-8116,
CVE-2014-8117, CVE-2014-9653)

Red Hat would like to thank Thomas Jarosch of Intra2net AG for
reporting the CVE-2014-8116 and CVE-2014-8117 issues. The
CVE-2014-0207, CVE-2014-0237, CVE-2014-0238, CVE-2014-3478,
CVE-2014-3479, CVE-2014-3480, CVE-2014-3487, CVE-2014-3710 issues were
discovered by Francisco Alonso of Red Hat Product Security; the
CVE-2014-3538 issue was discovered by Jan Kaluza of the Red Hat Web
Stack Team

The file packages have been updated to ensure correct operation on
Power little endian and ARM 64-bit hardware architectures.
(BZ#1224667, BZ#1224668, BZ#1157850, BZ#1067688).

All file users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002218.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6f224a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-magic");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"file-5.11-31.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"file-devel-5.11-31.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"file-libs-5.11-31.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"file-static-5.11-31.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-magic-5.11-31.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
