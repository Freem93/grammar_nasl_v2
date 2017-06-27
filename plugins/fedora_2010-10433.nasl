#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-10433.
#

include("compat.inc");

if (description)
{
  script_id(47720);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-1459");
  script_bugtraq_id(40351);
  script_osvdb_id(65051);
  script_xref(name:"FEDORA", value:"2010-10433");

  script_name(english:"Fedora 12 : mono-2.4.3.1-2.fc12 (2010-10433)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Jun 24 2010 Christian Krause <chkr at
    fedoraproject.org> - 2.4.3.1-2

    - Add upstream patch for CVE-2010-1459:
      http://anonsvn.mono-project.com/viewvc?view=revision&r
      evision=156450

  - Wed Jan 13 2010 Christian Krause <chkr at
    fedoraproject.org> - 2.4.3.1-1

    - Update to 2.4.3.1

    - Wed Dec 23 2009 Christian Krause <chkr at
      fedoraproject.org> - 2.4.3-1

    - Update to 2.4.3

    - Drop mono-242-metadata-appconf.patch (fixed upstream)

    - package mono.snk for packages without bundled keys to
      use

    - put mono.snk in /etc/pki/mono/

    - package /etc/pki/mono/* in mono-devel

    - change %gac_dll macro to be more specific about the
      files to package (necessary to correctly select all
      files for the moonlight subpackage without any
      dangling symlinks)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://anonsvn.mono-project.com/viewvc?view=revision&revision=156450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=598155"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044051.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dc66b36"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mono package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC12", reference:"mono-2.4.3.1-2.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mono");
}