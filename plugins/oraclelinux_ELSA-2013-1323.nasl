#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1323 and 
# Oracle Linux Security Advisory ELSA-2013-1323 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70285);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:16:05 $");

  script_cve_id("CVE-2010-4530");
  script_bugtraq_id(45806);
  script_xref(name:"RHSA", value:"2013:1323");

  script_name(english:"Oracle Linux 5 : ccid (ELSA-2013-1323)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1323 :

An updated ccid package that fixes one security issue and one bug is
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Chip/Smart Card Interface Devices (CCID) is a USB smart card reader
standard followed by most modern smart card readers. The ccid package
provides a Generic, USB-based CCID driver for readers, which follow
this standard.

An integer overflow, leading to an array index error, was found in the
way the CCID driver processed a smart card's serial number. A local
attacker could use this flaw to execute arbitrary code with the
privileges of the user running the PC/SC Lite pcscd daemon (root, by
default), by inserting a specially crafted smart card. (CVE-2010-4530)

This update also fixes the following bug :

* The pcscd service failed to read from the SafeNet Smart Card 650 v1
when it was inserted into a smart card reader. The operation failed
with a 'IFDHPowerICC() PowerUp failed' error message. This was due to
the card taking a long time to respond with a full Answer To Reset
(ATR) request, which lead to a timeout, causing the card to fail to
power up. This update increases the timeout value so that the
aforementioned request is processed properly, and the card is powered
on as expected. (BZ#907821)

All ccid users are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-October/003702.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ccid package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ccid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL5", reference:"ccid-1.3.8-2.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ccid");
}
