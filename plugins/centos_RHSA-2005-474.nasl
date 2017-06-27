#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:474 and 
# CentOS Errata and Security Advisory 2005:474 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21829);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/07/20 14:56:45 $");

  script_cve_id("CVE-2005-0758", "CVE-2005-0953", "CVE-2005-1260");
  script_osvdb_id(15237, 16371, 16767);
  script_xref(name:"RHSA", value:"2005:474");

  script_name(english:"CentOS 3 / 4 : bzip2 (CESA-2005:474)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bzip2 packages that fix multiple issues are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

[Updated 13 February 2006] Replacement bzip2 packages for Red Hat
Enterprise Linux 4 have been created as the original erratum packages
did not fix CVE-2005-0758.

Bzip2 is a data compressor.

A bug was found in the way bzgrep processes file names. If a user can
be tricked into running bzgrep on a file with a carefully crafted file
name, arbitrary commands could be executed as the user running bzgrep.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0758 to this issue.

A bug was found in the way bzip2 modifies file permissions during
decompression. If an attacker has write access to the directory into
which bzip2 is decompressing files, it is possible for them to modify
permissions on files owned by the user running bzip2 (CVE-2005-0953).

A bug was found in the way bzip2 decompresses files. It is possible
for an attacker to create a specially crafted bzip2 file which will
cause bzip2 to cause a denial of service (by filling disk space) if
decompressed by a victim (CVE-2005-1260).

Users of Bzip2 should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d7312b5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ad6a7d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?161f7d00"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012650.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa42caef"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012663.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89d3fba9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012664.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efd8eb9f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/30");
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
if (rpm_check(release:"CentOS-3", reference:"bzip2-1.0.2-11.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bzip2-devel-1.0.2-11.EL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bzip2-libs-1.0.2-11.EL3.4")) flag++;

if (rpm_check(release:"CentOS-4", reference:"bzip2-1.0.2-13.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bzip2-devel-1.0.2-13.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bzip2-libs-1.0.2-13.EL4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
