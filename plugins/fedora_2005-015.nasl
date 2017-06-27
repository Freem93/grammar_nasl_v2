#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-015.
#

include("compat.inc");

if (description)
{
  script_id(16267);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");
  script_xref(name:"FEDORA", value:"2005-015");

  script_name(english:"Fedora Core 2 : enscript-1.6.1-25.2 (2005-015)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Erik Sjolund has discovered several security relevant problems in
enscript, a program to converts ASCII text to Postscript and other
formats. The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities :

  - CVE-2004-1184

    Unsanitised input can causes the execution of arbitrary
    commands via EPSF pipe support. This has been disabled,
    also upstream.

  - CVE-2004-1185

    Due to missing sanitising of filenames it is possible
    that a specially crafted filename can cause arbitrary
    commands to be executed.

  - CVE-2004-1186

    Multiple buffer overflows can cause the program to
    crash.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-January/000631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d592ba1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected enscript and / or enscript-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:enscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:enscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"enscript-1.6.1-25.2")) flag++;
if (rpm_check(release:"FC2", reference:"enscript-debuginfo-1.6.1-25.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "enscript / enscript-debuginfo");
}
