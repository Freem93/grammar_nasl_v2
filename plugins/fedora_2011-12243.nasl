#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-12243.
#

include("compat.inc");

if (description)
{
  script_id(56153);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:24:19 $");

  script_bugtraq_id(49216, 49218, 49219, 49223, 49224, 49226, 49227, 49239, 49242, 49243, 49245, 49246, 49248);
  script_xref(name:"FEDORA", value:"2011-12243");

  script_name(english:"Fedora 16 : firefox-6.0.2-1.fc16 / mozvoikko-1.9.0-7.fc16 / thunderbird-6.0.2-1.fc16 / etc (2011-12243)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The latest version of Firefox and Thunderbird has the following
changes :

  - Removed trust exceptions for certificates issued by
    Staat der Nederlanden (see bug mozbz#683449 and the
    security advisory)

    - Resolved an issue with gov.uk websites (see bug
      mozbz#669792)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/065590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?955f7e60"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/065591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bec071d7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/065592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44ac5eef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/065593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef888964"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC16", reference:"firefox-6.0.2-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"mozvoikko-1.9.0-7.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"thunderbird-6.0.2-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"xulrunner-6.0.2-1.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / mozvoikko / thunderbird / xulrunner");
}
