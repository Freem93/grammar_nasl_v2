#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:180. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12321);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-0374", "CVE-2002-0825");
  script_xref(name:"CERT", value:"738331");
  script_xref(name:"RHSA", value:"2002:180");

  script_name(english:"RHEL 2.1 : nss_ldap (RHSA-2002:180)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss_ldap packages are now available for Red Hat Linux Advanced
Server 2.1. These updates fix a potential buffer overflow which can
occur when nss_ldap is set to configure itself using information
stored in DNS as well as a format string bug in logging functions used
in pam_ldap.

[Updated 09 Jan 2003] Added fixed packages for the Itanium (IA64)
architecture.

[Updated 06 Feb 2003] Added fixed packages for Advanced Workstation
2.1

nss_ldap is a set of C library extensions that allow X.500 and LDAP
directory servers to be used as a primary source of aliases, ethers,
groups, hosts, networks, protocols, users, RPCs, services, and shadow
passwords (instead of or in addition to using flat files or NIS).

When versions of nss_ldap prior to nss_ldap-198 are configured without
a value for the 'host' setting, nss_ldap will attempt to configure
itself by using SRV records stored in DNS. When parsing the results of
the DNS query, nss_ldap does not check that data returned by the
server will fit into an internal buffer, leaving it vulnerable to a
buffer overflow The Common Vulnerabilities and Exposures project has
assigned the name CVE-2002-0825 to this issue.

When versions of nss_ldap prior to nss_ldap-199 are configured without
a value for the 'host' setting, nss_ldap will attempt to configure
itself by using SRV records stored in DNS. When parsing the results of
the DNS query, nss_ldap does not check that the data returned has not
been truncated by the resolver libraries to avoid a buffer overflow,
and may attempt to parse more data than is actually available, leaving
it vulnerable to a read buffer overflow.

Versions of pam_ldap prior to version 144 include a format string bug
in the logging function. The packages included in this erratum update
pam_ldap to version 144, fixing this bug. The Common Vulnerabilities
and Exposures project has assigned the name CVE-2002-0374 to this
issue.

All users of nss_ldap should update to these errata packages which are
not vulnerable to the above issues. These packages are based on
nss_ldap-189 with the addition of a backported security patch and
pam_ldap version 144.

Thanks to the nss_ldap and pam_ldap team at padl.com for providing
information about these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0374.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0825.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.padl.com/Articles/PotentialBufferOverflowin.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.padl.com/OSS/pam_ldap.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-180.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss_ldap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
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
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:180";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"nss_ldap-189-4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss_ldap");
  }
}
