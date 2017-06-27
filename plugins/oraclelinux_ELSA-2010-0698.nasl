#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0698 and 
# Oracle Linux Security Advisory ELSA-2010-0698 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68101);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2010-3069");
  script_bugtraq_id(43212);
  script_xref(name:"RHSA", value:"2010:0698");

  script_name(english:"Oracle Linux 5 : samba3x (ELSA-2010-0698)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0698 :

Updated samba3x packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A missing array boundary checking flaw was found in the way Samba
parsed the binary representation of Windows security identifiers
(SIDs). A malicious client could send a specially crafted SMB request
to the Samba server, resulting in arbitrary code execution with the
privileges of the Samba server (smbd). (CVE-2010-3069)

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, the smb service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-September/001647.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba3x packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"libtalloc-1.2.0-52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"libtalloc-devel-1.2.0-52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"libtdb-1.1.2-52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"libtdb-devel-1.1.2-52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-client-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-common-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-doc-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-domainjoin-gui-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-swat-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-winbind-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba3x-winbind-devel-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"tdb-tools-1.1.2-52.el5_5.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtalloc / libtalloc-devel / libtdb / libtdb-devel / samba3x / etc");
}
