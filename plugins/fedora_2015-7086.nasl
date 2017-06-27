#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-7086.
#

include("compat.inc");

if (description)
{
  script_id(83323);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/11/16 15:47:33 $");

  script_cve_id("CVE-2015-3306");
  script_xref(name:"FEDORA", value:"2015-7086");

  script_name(english:"Fedora 21 : proftpd-1.3.5-5.fc21 (2015-7086)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vadim Melihow reported a critical issue with proftpd installations
that use the mod_copy module's SITE CPFR/SITE CPTO commands; mod_copy
allows these commands to be used by unauthenticated clients

Upstream report: http://bugs.proftpd.org/show_bug.cgi?id=4169

Note that mod_copy is not loaded/enabled by default in the Fedora
package.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.proftpd.org/show_bug.cgi?id=4169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1212386"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86aa97d0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.3.5 Mod_Copy Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"proftpd-1.3.5-5.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd");
}
