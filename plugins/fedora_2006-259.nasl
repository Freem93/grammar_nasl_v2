#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-259.
#

include("compat.inc");

if (description)
{
  script_id(21169);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_cve_id("CVE-2006-1059");
  script_xref(name:"FEDORA", value:"2006-259");

  script_name(english:"Fedora Core 5 : samba-3.0.22-1.fc5 (2006-259)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"---------------------------------------------------------------------

  - Thu Mar 30 2006 Jay Fenlason <fenlason at redhat.com>
    2.0.21c-1.fc5

    - New upstream version, fixing bz#187170 CVE-2005-1059
      Samba clear text password exposure

  - include gnutls-devel in BuildRequires

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-March/001962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6213f30"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC5", reference:"samba-3.0.22-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-client-3.0.22-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-common-3.0.22-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-debuginfo-3.0.22-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-swat-3.0.22-1.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / samba-client / samba-common / samba-debuginfo / samba-swat");
}
