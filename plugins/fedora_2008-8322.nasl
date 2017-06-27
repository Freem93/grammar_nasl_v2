#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-8322.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34305);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:23:17 $");

  script_cve_id("CVE-2008-4094");
  script_bugtraq_id(31176);
  script_xref(name:"FEDORA", value:"2008-8322");

  script_name(english:"Fedora 9 : rubygem-actionmailer-2.1.1-1.fc9 / rubygem-actionpack-2.1.1-1.fc9 / etc (2008-8322)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes CVE-2008-4094 (SQL injection in limit and offset clauses)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462308"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c28d96e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26a86463"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014849.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?284f68c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96225701"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014851.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89653b26"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b19a2329"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014853.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d43f96d3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygems");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"rubygem-actionmailer-2.1.1-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"rubygem-actionpack-2.1.1-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"rubygem-activerecord-2.1.1-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"rubygem-activeresource-2.1.1-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"rubygem-activesupport-2.1.1-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"rubygem-rails-2.1.1-2.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"rubygems-1.2.0-2.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-actionmailer / rubygem-actionpack / rubygem-activerecord / etc");
}
