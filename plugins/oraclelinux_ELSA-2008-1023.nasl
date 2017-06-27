#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:1023 and 
# Oracle Linux Security Advisory ELSA-2008-1023 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67774);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-2955", "CVE-2008-2957", "CVE-2008-3532");
  script_osvdb_id(47008);
  script_xref(name:"RHSA", value:"2008:1023");

  script_name(english:"Oracle Linux 4 : pidgin (ELSA-2008-1023)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:1023 :

Updated Pidgin packages that fix several security issues and bugs are
now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is a multi-protocol Internet Messaging client.

A denial-of-service flaw was found in Pidgin's MSN protocol handler.
If a remote user was able to send, and the Pidgin user accepted, a
carefully-crafted file request, it could result in Pidgin crashing.
(CVE-2008-2955)

A denial-of-service flaw was found in Pidgin's Universal Plug and Play
(UPnP) request handling. A malicious UPnP server could send a request
to Pidgin, causing it to download an excessive amount of data,
consuming all available memory or disk space. (CVE-2008-2957)

A flaw was found in the way Pidgin handled SSL certificates. The NSS
SSL implementation in Pidgin did not properly verify the authenticity
of SSL certificates. This could have resulted in users unknowingly
connecting to a malicious SSL service. (CVE-2008-3532)

In addition, this update upgrades pidgin from version 2.3.1 to version
2.5.2, with many additional stability and functionality fixes from the
Pidgin Project.

Note: the Secure Internet Live Conferencing (SILC) chat network
protocol has recently changed, affecting all versions of pidgin
shipped with Red Hat Enterprise Linux.

Pidgin cannot currently connect to the latest version of the SILC
server (1.1.14): it fails to properly exchange keys during initial
login. This update does not correct this. Red Hat Bugzilla #474212
(linked to in the References section) has more information.

Note: after the errata packages are installed, Pidgin must be
restarted for the update to take effect.

All Pidgin users should upgrade to these updated packages, which
contains Pidgin version 2.5.2 and resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-December/000832.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/15");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"finch-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"finch-devel-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-devel-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-perl-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-tcl-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-devel-2.5.2-6.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-perl-2.5.2-6.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
