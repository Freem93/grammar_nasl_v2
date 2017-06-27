#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2111 and 
# Oracle Linux Security Advisory ELSA-2015-2111 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87022);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2015-1345");
  script_osvdb_id(117534);
  script_xref(name:"RHSA", value:"2015:2111");

  script_name(english:"Oracle Linux 7 : grep (ELSA-2015-2111)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2111 :

Updated grep packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The grep utility searches through textual input for lines that contain
a match to a specified pattern and then prints the matching lines. The
GNU grep utilities include grep, egrep, and fgrep.

A heap-based buffer overflow flaw was found in the way grep processed
certain pattern and text combinations. An attacker able to trick a
user into running grep on specially crafted input could use this flaw
to crash grep or, potentially, read from uninitialized memory.
(CVE-2015-1345)

This update also fixes the following bugs :

* Prior to this update, the \w and \W symbols were inconsistently
matched to the [:alnum:] character class. Consequently, using regular
expressions with '\w' and '\W' could lead to incorrect results. With
this update, '\w' is consistently matched to the [_[:alnum:]]
character, and '\W' is consistently matched to the [^_[:alnum:]]
character. (BZ#1159012)

* Previously, the Perl Compatible Regular Expression (PCRE) matcher
(selected by the '-P' parameter in grep) did not work correctly when
matching non-UTF-8 text in UTF-8 locales. Consequently, an error
message about invalid UTF-8 byte sequence characters was returned. To
fix this bug, patches from upstream have been applied to the grep
utility. As a result, PCRE now skips non-UTF-8 characters as
non-matching text without returning any error message. (BZ#1217080)

All grep users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005555.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected grep package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grep");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"grep-2.20-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grep");
}
