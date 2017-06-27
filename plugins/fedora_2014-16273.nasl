#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-16273.
#

include("compat.inc");

if (description)
{
  script_id(79930);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:23:30 $");

  script_cve_id("CVE-2014-8104");
  script_xref(name:"FEDORA", value:"2014-16273");

  script_name(english:"Fedora 20 : openvpn-2.3.6-1.fc20 / pkcs11-helper-1.11-3.fc20 (2014-16273)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix for CVE-2014-8104.

https://community.openvpn.net/openvpn/wiki/SecurityAnnouncement-97597e
732b

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1169487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1169488"
  );
  # https://community.openvpn.net/openvpn/wiki/SecurityAnnouncement-97597e732b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f3c40e7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146072.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4eef1da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146073.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f083f509"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openvpn and / or pkcs11-helper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pkcs11-helper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"openvpn-2.3.6-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"pkcs11-helper-1.11-3.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn / pkcs11-helper");
}
