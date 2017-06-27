#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0108 and 
# Oracle Linux Security Advisory ELSA-2010-0108 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67996);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-4144", "CVE-2009-4145");
  script_xref(name:"RHSA", value:"2010:0108");

  script_name(english:"Oracle Linux 5 : NetworkManager (ELSA-2010-0108)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0108 :

Updated NetworkManager packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

NetworkManager is a network link manager that attempts to keep a wired
or wireless network connection active at all times.

A missing network certificate verification flaw was found in
NetworkManager. If a user created a WPA Enterprise or 802.1x wireless
network connection that was verified using a Certificate Authority
(CA) certificate, and then later removed that CA certificate file,
NetworkManager failed to verify the identity of the network on the
following connection attempts. In these situations, a malicious
wireless network spoofing the original network could trick a user into
disclosing authentication credentials or communicating over an
untrusted network. (CVE-2009-4144)

An information disclosure flaw was found in NetworkManager's
nm-connection-editor D-Bus interface. If a user edited network
connection options using nm-connection-editor, a summary of those
changes was broadcasted over the D-Bus message bus, possibly
disclosing sensitive information (such as wireless network
authentication credentials) to other local users. (CVE-2009-4145)

Users of NetworkManager should upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-February/001358.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected networkmanager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(200, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
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
if (rpm_check(release:"EL5", reference:"NetworkManager-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"NetworkManager-devel-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"NetworkManager-glib-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"NetworkManager-glib-devel-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"NetworkManager-gnome-0.7.0-9.el5_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-devel / NetworkManager-glib / etc");
}
