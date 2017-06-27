#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-20151.
#

include("compat.inc");

if (description)
{
  script_id(63309);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/20 13:54:17 $");

  script_cve_id("CVE-2012-2733", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");
  script_bugtraq_id(56402, 56403, 56812, 56813, 56814);
  script_xref(name:"FEDORA", value:"2012-20151");

  script_name(english:"Fedora 16 : tomcat-7.0.33-1.fc16 (2012-20151)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Updated to 7.0.33

    - Resolves: rhbz 873620 need chkconfig for
      update-alternatives

    - Resolves: rhbz 883676,883691,883704,873707 fix several
      security issues

    - Resolves: rhbz 883806 refix logdir ownership

    - Resolves: rhbz 820119 Remove bundled
      apache-commons-dbcp

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=873664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=873695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=883634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=883636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=883637"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-December/094893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bbf6a2f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC16", reference:"tomcat-7.0.33-1.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");
}
