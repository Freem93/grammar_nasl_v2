#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-506.
#

include("compat.inc");

if (description)
{
  script_id(25233);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_cve_id("CVE-2007-2444", "CVE-2007-2447");
  script_xref(name:"FEDORA", value:"2007-506");

  script_name(english:"Fedora Core 5 : samba-3.0.24-5.fc5 (2007-506)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release of Samba fixes some Serious security bugs :

  - CVE-2007-2444

    - CVE-2007-2446

    - CVE-2007-2447

Official upstream announcements here:
http://www.samba.org/samba/security/CVE-2007-2444.html
http://www.samba.org/samba/security/CVE-2007-2446.html
http://www.samba.org/samba/security/CVE-2007-2447.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2007-2444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2007-2446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2007-2447.html"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-May/001729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f20d49ad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"samba-3.0.24-5.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-client-3.0.24-5.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-common-3.0.24-5.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-debuginfo-3.0.24-5.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-swat-3.0.24-5.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / samba-client / samba-common / samba-debuginfo / samba-swat");
}
