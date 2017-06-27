#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1917 and 
# CentOS Errata and Security Advisory 2015:1917 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86485);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_osvdb_id(122812, 123385, 123541, 123542);
  script_xref(name:"RHSA", value:"2015:1917");

  script_name(english:"CentOS 6 / 7 : libwmf (CESA-2015:1917)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libwmf packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

libwmf is a library for reading and converting Windows Metafile Format
(WMF) vector graphics. libwmf is used by applications such as GIMP and
ImageMagick.

It was discovered that libwmf did not correctly process certain WMF
(Windows Metafiles) with embedded BMP images. By tricking a victim
into opening a specially crafted WMF file in an application using
libwmf, a remote attacker could possibly use this flaw to execute
arbitrary code with the privileges of the user running the
application. (CVE-2015-0848, CVE-2015-4588)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash or execute arbitrary code with the
privileges of the user running the application. (CVE-2015-4696)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash. (CVE-2015-4695)

All users of libwmf are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the update, all applications using libwmf must be restarted
for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-October/021434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?658454ce"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-October/021435.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63d79c4a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwmf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwmf-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");
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
if (rpm_check(release:"CentOS-6", reference:"libwmf-0.2.8.4-25.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libwmf-devel-0.2.8.4-25.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libwmf-lite-0.2.8.4-25.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwmf-0.2.8.4-41.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwmf-devel-0.2.8.4-41.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwmf-lite-0.2.8.4-41.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
