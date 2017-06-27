#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:583. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16017);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:55:16 $");

  script_cve_id("CVE-2004-0946", "CVE-2004-1014");
  script_osvdb_id(12240, 12351);
  script_xref(name:"RHSA", value:"2004:583");

  script_name(english:"RHEL 3 : nfs-utils (RHSA-2004:583)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated nfs-utils package that fixes various security issues is now
available.

The nfs-utils package provides a daemon for the kernel NFS server and
related tools, providing a much higher level of performance than the
traditional Linux NFS server used by most users.

This package also contains the showmount program. Showmount queries
the mount daemon on a remote host for information about the NFS
(Network File System) server on the remote host.

SGI reported that the statd daemon did not properly handle the SIGPIPE
signal. A misconfigured or malicious peer could cause statd to crash,
leading to a denial of service. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-1014
to this issue.

Arjan van de Ven discovered a buffer overflow in rquotad. On 64-bit
architectures, an improper integer conversion can lead to a buffer
overflow. An attacker with access to an NFS share could send a
specially crafted request which could lead to the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0946 to this issue.

Additionally, this updated package addresses the following issues :

  - The UID of the nfsnobody account has been fixed for
    32-bit and 64-bit machines. Because the st_uid field of
    the stat structure is an unsigned integer, an actual
    value of -2 cannot be used when creating the account, so
    the decimal value of -2 is used. On a 32-bit machine,
    the decimal value of -2 is 65534 but on a 64-bit machine
    it is 4294967294. This errata enables the nfs-utils
    post-install script to detect the target architecture,
    so an appropriate decimal value is used.

All users of nfs-utils should upgrade to this updated package, which
resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0946.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-583.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/22");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:583";
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
  if (rpm_check(release:"RHEL3", reference:"nfs-utils-1.0.6-33EL")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nfs-utils");
  }
}
