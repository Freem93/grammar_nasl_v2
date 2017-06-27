#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-21122.
#

include("compat.inc");

if (description)
{
  script_id(63460);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:27:59 $");

  script_bugtraq_id(56680);
  script_xref(name:"FEDORA", value:"2012-21122");

  script_name(english:"Fedora 16 : php-pear-CAS-1.3.2-1.fc16 (2012-21122)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in version 1.3.2

Security Fixes :

  - CVE-2012-5583 Missing CN validation of CAS server
    certificate [#58] (Joachim Fritschi)

Bug Fixes :

  - Fix broken character encoding in Greek and French [#40]
    (Joachim Fritschi)

    - Minor error corrections in a few example files []
      (Joachim Fritschi)

    - Remove erroneous break statement [#44] (jbittel)

    - Use X-Forwarded-Port [#45] (Andrew Kirkpatrick)

    - Stop autoloader using set_include_path [#51/#52]
      (drysdaleb)

    - Fix undefined property in the rebroadcast code [#47]
      (Joachim Fritschi)

Improvement :

  - Enable getCookies on a proxied sevices [#56] (Adam
    Franco)

Changes in version 1.3.1

Bug Fixes :

  - Readd PEAR support to the package [#30] (Joachim
    Fritschi)

    - fix a __autoload conflicts in the autoloader [#36]
      (Joachim Fritschi)

    - fix PEAR code style errors [25] (Joachim Fritschi)

    - properly unset variables during checkAuthenticate[#35]
      (Joachim Fritschi)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/095491.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79b5766a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear-CAS package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-CAS");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"php-pear-CAS-1.3.2-1.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear-CAS");
}
