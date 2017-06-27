#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-0358.
#

include("compat.inc");

if (description)
{
  script_id(50669);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:05:29 $");

  script_cve_id("CVE-2009-5018", "CVE-2010-4694", "CVE-2010-4695");
  script_osvdb_id(63300);
  script_xref(name:"FEDORA", value:"2010-0358");

  script_name(english:"Fedora 12 : gif2png-2.5.1-1202.fc12 (2010-0358)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Jan 5 2010 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de> - 2.5.1-1202

    - catch another possible overflow when appending a
      numbered suffix (detected to Tomas Hoger)

  - Sat Jan 2 2010 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de> - 2.5.1-1201

    - changed -overflow patch to abort on bad filenames
      instead of processing truncated ones

  - Fri Jan 1 2010 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de> - 2.5.1-1200

    - fixed command line buffer overflow (#547515)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=547515"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/051229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc789a43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gif2png package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gif2png");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"gif2png-2.5.1-1202.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gif2png");
}
