#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0103 and 
# Oracle Linux Security Advisory ELSA-2014-0103 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72195);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 17:25:13 $");

  script_cve_id("CVE-2013-6458", "CVE-2014-1447");
  script_bugtraq_id(64723, 64945);
  script_osvdb_id(101853, 102184);
  script_xref(name:"RHSA", value:"2014:0103");

  script_name(english:"Oracle Linux 6 : libvirt (ELSA-2014-0103)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0103 :

Updated libvirt packages that fix two security issues and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

A use-after-free flaw was found in the way several libvirt block APIs
handled domain jobs. A remote attacker able to establish a read-only
connection to libvirtd could use this flaw to crash libvirtd or,
potentially, execute arbitrary code with the privileges of the
libvirtd process (usually root). (CVE-2013-6458)

A race condition was found in the way libvirtd handled keepalive
initialization requests when the connection was closed prior to
establishing connection credentials. An attacker able to establish a
read-only connection to libvirtd could use this flaw to crash
libvirtd, resulting in a denial of service. (CVE-2014-1447)

This update also fixes the following bug :

* A race condition was possible between a thread starting a virtual
machine with a guest agent configured (regular start-up or while
migrating) and a thread that was killing the VM process (or the
process crashing). The race could cause the monitor object to be freed
by the thread that killed the VM process, which was later accessed by
the thread that was attempting to start the VM, resulting in a crash.
This issue was fixed by checking the state of the VM after the
attempted connection to the guest agent; if the VM in the meantime
exited, no other operations are attempted. (BZ#1055578)

All libvirt users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-January/003927.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libvirt-0.10.2-29.0.1.el6_5.3")) flag++;
if (rpm_check(release:"EL6", reference:"libvirt-client-0.10.2-29.0.1.el6_5.3")) flag++;
if (rpm_check(release:"EL6", reference:"libvirt-devel-0.10.2-29.0.1.el6_5.3")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-29.0.1.el6_5.3")) flag++;
if (rpm_check(release:"EL6", reference:"libvirt-python-0.10.2-29.0.1.el6_5.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-devel / libvirt-lock-sanlock / etc");
}
