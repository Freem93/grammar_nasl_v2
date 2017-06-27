#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1930 and 
# Oracle Linux Security Advisory ELSA-2015-1930 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86612);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/06/13 13:30:10 $");

  script_cve_id("CVE-2015-5300", "CVE-2015-7704");
  script_osvdb_id(129309, 129315);
  script_xref(name:"RHSA", value:"2015:1930");

  script_name(english:"Oracle Linux 6 / 7 : ntp (ELSA-2015-1930)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1930 :

Updated ntp packages that fix two security issues are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a referenced time source.

It was discovered that ntpd as a client did not correctly check
timestamps in Kiss-of-Death packets. A remote attacker could use this
flaw to send a crafted Kiss-of-Death packet to an ntpd client that
would increase the client's polling interval value, and effectively
disable synchronization with the server. (CVE-2015-7704)

It was found that ntpd did not correctly implement the threshold
limitation for the '-g' option, which is used to set the time without
any restrictions. A man-in-the-middle attacker able to intercept NTP
traffic between a connecting client and an NTP server could use this
flaw to force that client to make multiple steps larger than the panic
threshold, effectively changing the time to an arbitrary value.
(CVE-2015-5300)

Red Hat would like to thank Aanchal Malhotra, Isaac E. Cohen, and
Sharon Goldberg of Boston University for reporting these issues.

All ntp users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
the update, the ntpd daemon will restart automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-October/005473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-October/005474.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/27");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"ntp-4.2.6p5-5.el6_7.2")) flag++;
if (rpm_check(release:"EL6", reference:"ntp-doc-4.2.6p5-5.el6_7.2")) flag++;
if (rpm_check(release:"EL6", reference:"ntp-perl-4.2.6p5-5.el6_7.2")) flag++;
if (rpm_check(release:"EL6", reference:"ntpdate-4.2.6p5-5.el6_7.2")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ntp-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ntp-doc-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sntp-4.2.6p5-19.el7_1.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-doc / ntp-perl / ntpdate / sntp");
}
