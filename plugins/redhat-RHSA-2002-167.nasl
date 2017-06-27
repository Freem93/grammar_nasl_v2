#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:167. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12318);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-0391", "CVE-2002-0651", "CVE-2002-0684");
  script_osvdb_id(34753);
  script_xref(name:"CERT-CC", value:"CA-2002-19");
  script_xref(name:"RHSA", value:"2002:167");

  script_name(english:"RHEL 2.1 : glibc (RHSA-2002:167)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages are available which fix a buffer overflow in
the XDR decoder and two vulnerabilities in the resolver functions.

[updated 8 aug 2002] Updated packages have been made available, as the
original errata introduced a bug which could cause calloc() to crash
on 32-bit platforms when passed a size of 0. These updated errata
packages contain a patch to correct this bug.

The glibc package contains standard libraries which are used by
multiple programs on the system. Sun RPC is a remote procedure call
framework which allows clients to invoke procedures in a server
process over a network. XDR is a mechanism for encoding data
structures for use with RPC. NFS, NIS, and other network services that
are built upon Sun RPC. The glibc package contains an XDR
encoder/decoder derived from Sun's RPC implementation which was
recently demonstrated to be vulnerable to a heap overflow.

An error in the calculation of memory needed for unpacking arrays in
the XDR decoder can result in a heap buffer overflow in glibc 2.2.5
and earlier. Depending upon the application, this vulnerability may be
exploitable and could lead to arbitrary code execution.
(CVE-2002-0391)

A buffer overflow vulnerability has been found in the way the glibc
resolver handles the resolution of network names and addresses via DNS
(as per Internet RFC 1011). Version 2.2.5 of glibc and earlier
versions are affected. A system would be vulnerable to this issue if
the 'networks' database in the /etc/nsswitch.conf file includes the
'dns' entry. By default, Red Hat Linux Advanced Server ships with
'networks' set to 'files' and is therefore not vulnerable to this
issue. (CVE-2002-0684)

A related issue is a bug in the glibc-compat packages, which provide
compatibility for applications compiled against glibc version 2.0.x.
Applications compiled against this version (such as those distributed
with early Red Hat Linux releases 5.0, 5.1, and 5.2) could also be
vulnerable to this issue. (CVE-2002-0651)

All users should upgrade to these errata packages which contain
patches to the glibc libraries and therefore are not vulnerable to
these issues.

Thanks to Solar Designer for providing patches for this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0391.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0651.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0684.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/285308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sources.redhat.com/ml/libc-hacker/2002-08/msg00093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-167.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:167";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-2.2.4-29.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"glibc-2.2.4-29.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-common-2.2.4-29.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-devel-2.2.4-29.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-profile-2.2.4-29.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"nscd-2.2.4-29.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-profile / nscd");
  }
}
