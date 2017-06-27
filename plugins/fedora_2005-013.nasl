#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-013.
#

include("compat.inc");

if (description)
{
  script_id(16133);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_cve_id("CVE-2004-1235");
  script_xref(name:"FEDORA", value:"2005-013");

  script_name(english:"Fedora Core 3 : kernel-2.6.10-1.737_FC3 (2005-013)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update rebases the kernel to match the upstream 2.6.10 release,
and adds a number of security fixes by means of adding the latest -ac
patch.

CVE-2004-1235 Paul Starzetz from isec.pl found a problem in the binary
format loaders uselib() function that could lead to potential
priveledge escalation.
http://isec.pl/vulnerabilities/isec-0021-uselib.txt

NO-CAN-ASSIGNED Brad Spengler found several problems.

  - An integer overflow in the random poolsize sysctl
    handler.

    - SCSI ioctl integer overflow and information leak.

    - RLIMIT_MEMLOCK bypass and unprivileged user DoS.

NO-CAN-ASSIGNED Coverity Inc. found a number of bugs with their
automated source checker in coda, xfs, network bridging, rose network
protocol, and the sdla wan driver. http://linuxbugs.coverity.com

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0021-uselib.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://linuxbugs.coverity.com"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-January/000571.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8eaa2334"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"kernel-2.6.10-1.737_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-debuginfo-2.6.10-1.737_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-doc-2.6.10-1.737_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-smp-2.6.10-1.737_FC3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-doc / kernel-smp");
}
