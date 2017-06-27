#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-18432.
#

include("compat.inc");

if (description)
{
  script_id(63046);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:27:59 $");

  script_cve_id("CVE-2012-4548");
  script_bugtraq_id(56315);
  script_xref(name:"FEDORA", value:"2012-18432");

  script_name(english:"Fedora 18 : cgit-0.9.1-2.fc18 (2012-18432)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix syntax highlight script to use correct version of highlight.
Update to new upsteam version with 2 security fixes, enhancements and
misc other bug fixes. See
http://git.zx2c4.com/cgit/commit/?id=a6a932e198e8b6b564d7a4bb43e78078d
8296026 for details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://git.zx2c4.com/cgit/commit/?id=a6a932e198e8b6b564d7a4bb43e78078d8296026
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c470b4c7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=820733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=870714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=877647"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/092698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b96ec5b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cgit package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cgit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/26");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"cgit-0.9.1-2.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cgit");
}
