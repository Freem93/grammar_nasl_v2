#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-522.
#

include("compat.inc");

if (description)
{
  script_id(83280);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/05/20 15:11:00 $");

  script_cve_id("CVE-2015-3627", "CVE-2015-3629", "CVE-2015-3630", "CVE-2015-3631");
  script_xref(name:"ALAS", value:"2015-522");

  script_name(english:"Amazon Linux AMI : docker (ALAS-2015-522)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The file-descriptor passed by libcontainer to the pid-1 process of a
container has been found to be opened prior to performing the chroot,
allowing insecure open and symlink traversal. This allows malicious
container images to trigger a local privilege escalation.
(CVE-2015-3627)

Libcontainer version 1.6.0 introduced changes which facilitated a
mount namespace breakout upon respawn of a container. This allowed
malicious images to write files to the host system and escape
containerization. (CVE-2015-3629)

Several paths underneath /proc were writable from containers, allowing
global system manipulation and configuration. These paths included
/proc/asound, /proc/timer_stats, /proc/latency_stats, and /proc/fs. By
allowing writes to /proc/fs, it has been noted that CIFS volumes could
be forced into a protocol downgrade attack by a root user operating
inside of a container. Machines having loaded the timer_stats module
were vulnerable to having this mechanism enabled and consumed by a
container. (CVE-2015-3630)

By allowing volumes to override files of /proc within a mount
namespace, a user could specify arbitrary policies for Linux Security
Modules, including setting an unconfined policy underneath AppArmor,
or a docker_t policy for processes managed by SELinux. In all versions
of Docker up until 1.6.1, it is possible for malicious images to
configure volume mounts such that files of proc may be overridden.
(CVE-2015-3631)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-522.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update docker' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-1.6.0-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-devel-1.6.0-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-pkg-devel-1.6.0-1.3.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-devel / docker-pkg-devel");
}
