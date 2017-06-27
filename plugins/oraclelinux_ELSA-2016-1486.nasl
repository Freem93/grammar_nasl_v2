#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1486 and 
# Oracle Linux Security Advisory ELSA-2016-1486 respectively.
#

include("compat.inc");

if (description)
{
  script_id(92576);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/27 14:39:36 $");

  script_cve_id("CVE-2016-2119");
  script_osvdb_id(141072);
  script_xref(name:"RHSA", value:"2016:1486");

  script_name(english:"Oracle Linux 7 : samba (ELSA-2016-1486)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1486 :

An update for samba is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* A flaw was found in the way Samba initiated signed DCE/RPC
connections. A man-in-the-middle attacker could use this flaw to
downgrade the connection to not use signing and therefore impersonate
the server. (CVE-2016-2119)

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges Stefan Metzmacher as the original
reporter.

Bug Fix(es) :

* Previously, the 'net' command in some cases failed to join the
client to Active Directory (AD) because the permissions setting
prevented modification of the supported Kerberos encryption type LDAP
attribute. With this update, Samba has been fixed to allow joining an
AD domain as a user. In addition, Samba now uses the machine account
credentials to set up the Kerberos encryption types within AD for the
joined machine. As a result, using 'net' to join a domain now works
more reliably. (BZ#1351260)

* Previously, the idmap_hash module worked incorrectly when it was
used together with other modules. As a consequence, user and group IDs
were not mapped properly. A patch has been applied to skip already
configured modules. Now, the hash module can be used as the default
idmap configuration back end and IDs are resolved correctly.
(BZ#1350759)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-July/006209.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ctdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ctdb-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ctdb-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ctdb-tests-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsmbclient-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsmbclient-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwbclient-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwbclient-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-client-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-client-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-common-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-common-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-common-tools-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-dc-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-dc-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-pidl-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-python-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-test-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-test-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-test-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-clients-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-modules-4.2.10-7.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-devel / ctdb-tests / libsmbclient / libsmbclient-devel / etc");
}
