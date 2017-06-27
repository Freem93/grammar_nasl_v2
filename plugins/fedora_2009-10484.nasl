#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-10484.
#

include("compat.inc");

if (description)
{
  script_id(42128);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:32:48 $");

  script_cve_id("CVE-2009-3009");
  script_bugtraq_id(36278);
  script_xref(name:"FEDORA", value:"2009-10484");

  script_name(english:"Fedora 11 : rubygem-actionmailer-2.3.2-3.fc11 / rubygem-actionpack-2.3.2-2.fc11 / etc (2009-10484)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fixes CVE-2009-3009 - Downgrade to Rails 2.3.2 to avoid
    update issues for existing applications

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=520843"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40f04b14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030058.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a6a9293"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02639cae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?730621f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030061.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0207dcc7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030062.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?947f18bc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"rubygem-actionmailer-2.3.2-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"rubygem-actionpack-2.3.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"rubygem-activerecord-2.3.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"rubygem-activeresource-2.3.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"rubygem-activesupport-2.3.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"rubygem-rails-2.3.2-5.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-actionmailer / rubygem-actionpack / rubygem-activerecord / etc");
}
