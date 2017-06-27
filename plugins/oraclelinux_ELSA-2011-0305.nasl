#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0305 and 
# Oracle Linux Security Advisory ELSA-2011-0305 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68208);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2011-0719");
  script_bugtraq_id(46597);
  script_osvdb_id(71268);
  script_xref(name:"RHSA", value:"2011:0305");

  script_name(english:"Oracle Linux 4 / 5 / 6 : samba (ELSA-2011-0305)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0305 :

Updated samba packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A flaw was found in the way Samba handled file descriptors. If an
attacker were able to open a large number of file descriptors on the
Samba server, they could flip certain stack bits to '1' values,
resulting in the Samba server (smbd) crashing. (CVE-2011-0719)

Red Hat would like to thank the Samba team for reporting this issue.

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, the smb service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-March/001957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-March/001965.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-March/001966.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/03");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"samba-3.0.33-0.30.el4")) flag++;
if (rpm_check(release:"EL4", reference:"samba-client-3.0.33-0.30.el4")) flag++;
if (rpm_check(release:"EL4", reference:"samba-common-3.0.33-0.30.el4")) flag++;
if (rpm_check(release:"EL4", reference:"samba-swat-3.0.33-0.30.el4")) flag++;

if (rpm_check(release:"EL5", reference:"libsmbclient-3.0.33-3.29.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"libsmbclient-devel-3.0.33-3.29.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba-3.0.33-3.29.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba-client-3.0.33-3.29.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba-common-3.0.33-3.29.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"samba-swat-3.0.33-3.29.el5_6.2")) flag++;

if (rpm_check(release:"EL6", reference:"libsmbclient-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"libsmbclient-devel-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-client-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-common-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-doc-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-domainjoin-gui-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-swat-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-winbind-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-winbind-clients-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"samba-winbind-devel-3.5.4-68.el6_0.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
}
