#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1827 and 
# Oracle Linux Security Advisory ELSA-2014-1827 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79200);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_bugtraq_id(70096);
  script_osvdb_id(112012, 112013, 112025, 112026);
  script_xref(name:"RHSA", value:"2014:1827");

  script_name(english:"Oracle Linux 7 : kdenetwork (ELSA-2014-1827)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1827 :

Updated kdenetwork packages that fix three security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kdenetwork packages contain networking applications for the K
Desktop Environment (KDE). Krfb Desktop Sharing, which is a part of
the kdenetwork package, is a server application that allows session
sharing between users. Krfb uses the LibVNCServer library.

A NULL pointer dereference flaw was found in the way LibVNCServer
handled certain ClientCutText message. A remote attacker could use
this flaw to crash the VNC server by sending a specially crafted
ClientCutText message from a VNC client. (CVE-2014-6053)

A divide-by-zero flaw was found in the way LibVNCServer handled the
scaling factor when it was set to '0'. A remote attacker could use
this flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6054)

Two stack-based buffer overflow flaws were found in the way
LibVNCServer handled file transfers. A remote attacker could use this
flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6055)

Red Hat would like to thank oCERT for reporting these issues. oCERT
acknowledges Nicolas Ruff as the original reporter.

Note: Prior to this update, the kdenetwork packages used an embedded
copy of the LibVNCServer library. With this update, the kdenetwork
packages have been modified to use the system LibVNCServer packages.
Therefore, the update provided by RHSA-2014:1826 must be installed to
fully address the issues in krfb described above.

All kdenetwork users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
instances of the krfb server must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-November/004628.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdenetwork packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-fileshare-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kget-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kopete-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kopete-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krdc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krdc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krfb-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-common-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-fileshare-samba-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-kdnssd-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-kget-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-kget-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-kopete-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-kopete-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-kopete-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-krdc-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-krdc-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-krdc-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-krfb-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kdenetwork-krfb-libs-4.10.5-8.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdenetwork / kdenetwork-common / kdenetwork-devel / etc");
}
