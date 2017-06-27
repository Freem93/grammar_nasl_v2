#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1508 and 
# Oracle Linux Security Advisory ELSA-2011-1508 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68397);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:58:00 $");

  script_cve_id("CVE-2011-3372", "CVE-2011-3481");
  script_bugtraq_id(49659, 49949);
  script_osvdb_id(75445, 76057);
  script_xref(name:"RHSA", value:"2011:1508");

  script_name(english:"Oracle Linux 4 / 5 / 6 : cyrus-imapd (ELSA-2011-1508)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1508 :

Updated cyrus-imapd packages that fix two security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and Sieve support.

An authentication bypass flaw was found in the cyrus-imapd NNTP
server, nntpd. A remote user able to use the nntpd service could use
this flaw to read or post newsgroup messages on an NNTP server
configured to require user authentication, without providing valid
authentication credentials. (CVE-2011-3372)

A NULL pointer dereference flaw was found in the cyrus-imapd IMAP
server, imapd. A remote attacker could send a specially crafted mail
message to a victim that would possibly prevent them from accessing
their mail normally, if they were using an IMAP client that relies on
the server threading IMAP feature. (CVE-2011-3481)

Red Hat would like to thank the Cyrus IMAP project for reporting the
CVE-2011-3372 issue. Upstream acknowledges Stefan Cornelius of Secunia
Research as the original reporter of CVE-2011-3372.

Users of cyrus-imapd are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the update, cyrus-imapd will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-December/002490.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-December/002491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-December/002492.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-nntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Cyrus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-2.2.12-17.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-devel-2.2.12-17.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-murder-2.2.12-17.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-nntp-2.2.12-17.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-utils-2.2.12-17.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"perl-Cyrus-2.2.12-17.0.1.el4")) flag++;

if (rpm_check(release:"EL5", reference:"cyrus-imapd-2.3.7-12.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-devel-2.3.7-12.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-perl-2.3.7-12.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-utils-2.3.7-12.0.1.el5_7.2")) flag++;

if (rpm_check(release:"EL6", reference:"cyrus-imapd-2.3.16-6.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"cyrus-imapd-devel-2.3.16-6.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"cyrus-imapd-utils-2.3.16-6.el6_1.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-devel / cyrus-imapd-murder / etc");
}
