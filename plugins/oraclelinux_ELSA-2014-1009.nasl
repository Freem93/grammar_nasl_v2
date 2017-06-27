#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1009 and 
# Oracle Linux Security Advisory ELSA-2014-1009 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77010);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/27 16:14:42 $");

  script_cve_id("CVE-2014-0178", "CVE-2014-0244", "CVE-2014-3493", "CVE-2014-3560");
  script_bugtraq_id(67686, 68148, 68150);
  script_xref(name:"RHSA", value:"2014:1009");

  script_name(english:"Oracle Linux 6 : samba4 (ELSA-2014-1009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1009 :

Updated samba4 packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A heap-based buffer overflow flaw was found in Samba's NetBIOS message
block daemon (nmbd). An attacker on the local network could use this
flaw to send specially crafted packets that, when processed by nmbd,
could possibly lead to arbitrary code execution with root privileges.
(CVE-2014-3560)

All Samba users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing this update, the smb service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-August/004331.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"samba4-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-client-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-common-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-dc-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-dc-libs-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-devel-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-libs-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-pidl-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-python-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-swat-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-test-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-winbind-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-winbind-clients-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-winbind-krb5-locator-4.0.0-63.el6_5.rc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
}
