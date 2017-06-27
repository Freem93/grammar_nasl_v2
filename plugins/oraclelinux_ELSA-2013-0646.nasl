#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0646 and 
# Oracle Linux Security Advisory ELSA-2013-0646 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68791);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");
  script_bugtraq_id(48425, 52475, 53400, 54322, 57951, 57954);
  script_osvdb_id(90231, 90233, 90234);
  script_xref(name:"RHSA", value:"2013:0646");

  script_name(english:"Oracle Linux 6 : pidgin (ELSA-2013-0646)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0646 :

Updated pidgin packages that fix three security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A stack-based buffer overflow flaw was found in the Pidgin MXit
protocol plug-in. A malicious server or a remote attacker could use
this flaw to crash Pidgin by sending a specially crafted HTTP request.
(CVE-2013-0272)

A buffer overflow flaw was found in the Pidgin Sametime protocol
plug-in. A malicious server or a remote attacker could use this flaw
to crash Pidgin by sending a specially crafted username.
(CVE-2013-0273)

A buffer overflow flaw was found in the way Pidgin processed certain
UPnP responses. A remote attacker could send a specially crafted UPnP
response that, when processed, would crash Pidgin. (CVE-2013-0274)

Red Hat would like to thank the Pidgin project for reporting the above
issues. Upstream acknowledges Daniel Atallah as the original reporter
of CVE-2013-0272.

All Pidgin users should upgrade to these updated packages, which
contain backported patches to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-March/003368.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"finch-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"finch-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-perl-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-tcl-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-docs-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-perl-2.7.9-10.el6_4.1")) flag++;


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
