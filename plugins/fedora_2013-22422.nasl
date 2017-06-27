#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-22422.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71255);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 21:37:40 $");

  script_cve_id("CVE-2013-5958");
  script_bugtraq_id(63005);
  script_xref(name:"FEDORA", value:"2013-22422");

  script_name(english:"Fedora 18 : php-symfony2-DependencyInjection-2.2.10-1.fc18 / etc (2013-22422)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated to 2.2.10

CVE-2013-5958

Release notes :

  - http://symfony.com/blog/symfony-2-2-10-released

    -
      http://symfony.com/blog/security-releases-CVE-2013-595
      8-symfony-2-0-25-2-1-13-2-2-9-and-2-3-6-released

    - http://symfony.com/blog/symfony-2-2-8-released

    - http://symfony.com/blog/symfony-2-2-6-released

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://symfony.com/blog/security-releases-CVE-2013-5958-symfony-2-0-25-2-1-13-2-2-9-and-2-3-6-released
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e0df36c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://symfony.com/blog/symfony-2-2-10-released"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://symfony.com/blog/symfony-2-2-6-released"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://symfony.com/blog/symfony-2-2-8-released"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5e40817"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ba77336"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17f8128a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123251.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a5890cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123252.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae38eead"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?986bb5dd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123254.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61d1c706"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123255.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4426506"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123256.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5e8df5c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123257.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a161749"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7979d37"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eff1220c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e90ae72"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8033db87"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97301038"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123263.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?366c37ee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54b27840"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d23aad3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f69497cc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?959b9659"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89132848"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbd8565c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5136a0b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb3783e2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-BrowserKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-ClassLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-CssSelector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-DependencyInjection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-DomCrawler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-EventDispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Finder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Form");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-HttpFoundation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-HttpKernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-OptionsResolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-PropertyAccess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Routing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Serializer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Templating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Translation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Yaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"php-symfony2-BrowserKit-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-ClassLoader-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Config-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Console-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-CssSelector-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-DependencyInjection-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-DomCrawler-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-EventDispatcher-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Filesystem-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Finder-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Form-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-HttpFoundation-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-HttpKernel-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Locale-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-OptionsResolver-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Process-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-PropertyAccess-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Routing-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Security-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Serializer-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Templating-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Translation-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Validator-2.2.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"php-symfony2-Yaml-2.2.10-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony2-BrowserKit / php-symfony2-ClassLoader / etc");
}
