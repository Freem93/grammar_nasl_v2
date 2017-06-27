#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0613. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90493);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118");
  script_osvdb_id(136339, 136989, 136990, 136991, 136992, 136995);
  script_xref(name:"RHSA", value:"2016:0613");

  script_name(english:"RHEL 5 : samba3x (RHSA-2016:0613) (Badlock)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba3x is now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

Security Fix(es) :

* Multiple flaws were found in Samba's DCE/RPC protocol
implementation. A remote, authenticated attacker could use these flaws
to cause a denial of service against the Samba server (high CPU load
or a crash) or, possibly, execute arbitrary code with the permissions
of the user running Samba (root). This flaw could also be used to
downgrade a secure DCE/RPC connection by a man-in-the-middle attacker
taking control of an Active Directory (AD) object and compromising the
security of a Samba Active Directory Domain Controller (DC).
(CVE-2015-5370)

Note: While Samba packages as shipped in Red Hat Enterprise Linux do
not support running Samba as an AD DC, this flaw applies to all roles
Samba implements.

* A protocol flaw, publicly referred to as Badlock, was found in the
Security Account Manager Remote Protocol (MS-SAMR) and the Local
Security Authority (Domain Policy) Remote Protocol (MS-LSAD). Any
authenticated DCE/RPC connection that a client initiates against a
server could be used by a man-in-the-middle attacker to impersonate
the authenticated user against the SAMR or LSA service on the server.
As a result, the attacker would be able to get read/write access to
the Security Account Manager database, and use this to reveal all
passwords or any other potentially sensitive information in that
database. (CVE-2016-2118)

* Several flaws were found in Samba's implementation of NTLMSSP
authentication. An unauthenticated, man-in-the-middle attacker could
use this flaw to clear the encryption and integrity flags of a
connection, causing data to be transmitted in plain text. The attacker
could also force the client or server into sending data in plain text
even if encryption was explicitly requested for that connection.
(CVE-2016-2110)

* It was discovered that Samba configured as a Domain Controller would
establish a secure communication channel with a machine using a
spoofed computer name. A remote attacker able to observe network
traffic could use this flaw to obtain session-related information
about the spoofed machine. (CVE-2016-2111)

* It was found that Samba's LDAP implementation did not enforce
integrity protection for LDAP connections. A man-in-the-middle
attacker could use this flaw to downgrade LDAP connections to use no
integrity protection, allowing them to hijack such connections.
(CVE-2016-2112)

* It was found that Samba did not enable integrity protection for IPC
traffic by default. A man-in-the-middle attacker could use this flaw
to view and modify the data sent between a Samba server and a client.
(CVE-2016-2115)

Red Hat would like to thank the Samba project for reporting these
issues. Upstream acknowledges Jouni Knuutinen (Synopsis) as the
original reporter of CVE-2015-5370; and Stefan Metzmacher (SerNet) as
the original reporter of CVE-2016-2118, CVE-2016-2110, CVE-2016-2112,
and CVE-2016-2115."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2111.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2118.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/badlock"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2253041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://badlock.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2243351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0613.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0613";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-client-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-client-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-client-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-common-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-common-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-common-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"samba3x-debuginfo-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-doc-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-doc-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-doc-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-domainjoin-gui-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-domainjoin-gui-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-domainjoin-gui-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-swat-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-swat-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-swat-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-3.6.23-12.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-devel-3.6.23-12.el5_11")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba3x / samba3x-client / samba3x-common / samba3x-debuginfo / etc");
  }
}
