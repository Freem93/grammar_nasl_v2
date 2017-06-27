#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-7b40eb9e29.
#

include("compat.inc");

if (description)
{
  script_id(90960);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/09 15:53:04 $");

  script_cve_id("CVE-2015-3455", "CVE-2015-5400");
  script_xref(name:"FEDORA", value:"2016-7b40eb9e29");

  script_name(english:"Fedora 22 : libecap-1.0.0-1.fc22 / squid-3.5.10-1.fc22 (2016-7b40eb9e29)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2016-2571, CVE-2016-2572 ---- squid-3.4.13-3.fc22
- Resolves: #1231992 ---- Security fix for #1240741, #1240744 Updated
to version 3.4.13, which fixes CVE-2015-3455

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1218118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1240741"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/183597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?314ae20e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/183598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51491c24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libecap and / or squid packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libecap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"libecap-1.0.0-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"squid-3.5.10-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecap / squid");
}
