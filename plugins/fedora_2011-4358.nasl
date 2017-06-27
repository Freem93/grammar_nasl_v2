#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-4358.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(53299);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:05:54 $");

  script_cve_id("CVE-2011-0446", "CVE-2011-0447", "CVE-2011-0448", "CVE-2011-0449");
  script_bugtraq_id(46291, 46292);
  script_xref(name:"FEDORA", value:"2011-4358");

  script_name(english:"Fedora 15 : rubygem-actionmailer-3.0.5-1.fc15 / rubygem-actionpack-3.0.5-1.fc15 / etc (2011-4358)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the Rails 3.0.5

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=677626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=677631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=679343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=679351"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?538e4888"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?042d2f6c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddfde9ed"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d67ec26"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3889a3d5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dff2718"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057649.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a128e09b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/057650.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f69b0d83"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"rubygem-actionmailer-3.0.5-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rubygem-actionpack-3.0.5-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rubygem-activemodel-3.0.5-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rubygem-activerecord-3.0.5-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rubygem-activeresource-3.0.5-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rubygem-activesupport-3.0.5-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rubygem-rails-3.0.5-2.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rubygem-railties-3.0.5-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-actionmailer / rubygem-actionpack / rubygem-activemodel / etc");
}
