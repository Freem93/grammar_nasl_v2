#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-166.
#

include("compat.inc");

if (description)
{
  script_id(69725);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-4398", "CVE-2012-4461", "CVE-2012-4530", "CVE-2013-0871");
  script_xref(name:"ALAS", value:"2013-166");
  script_xref(name:"RHSA", value:"2013:0223");
  script_xref(name:"RHSA", value:"2013:0567");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2013-166)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that a deadlock could occur in the Out of Memory (OOM)
killer. A process could trigger this deadlock by consuming a large
amount of memory, and then causing request_module() to be called. A
local, unprivileged user could use this flaw to cause a denial of
service (excessive memory consumption). (CVE-2012-4398)

A flaw was found in the way the KVM (Kernel-based Virtual Machine)
subsystem handled guests attempting to run with the X86_CR4_OSXSAVE
CPU feature flag set. On hosts without the XSAVE CPU feature, a local,
unprivileged user could use this flaw to crash the host system. (The
'grep --color xsave /proc/cpuinfo' command can be used to verify if
your system has the XSAVE CPU feature.) (CVE-2012-4461)

A memory disclosure flaw was found in the way the load_script()
function in the binfmt_script binary format handler handled excessive
recursions. A local, unprivileged user could use this flaw to leak
kernel stack memory to user-space by executing specially crafted
scripts. (CVE-2012-4530)

A race condition was found in the way the Linux kernel's ptrace
implementation handled PTRACE_SETREGS requests when the debuggee was
woken due to a SIGKILL signal instead of being stopped. A local,
unprivileged user could use this flaw to escalate their privileges.
(CVE-2013-0871)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-166.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.2.39-6.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.2.39-6.88.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
