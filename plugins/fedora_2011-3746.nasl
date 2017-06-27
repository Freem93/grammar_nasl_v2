#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-3746.
#

include("compat.inc");

if (description)
{
  script_id(53216);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:05:54 $");

  script_cve_id("CVE-2011-0700", "CVE-2011-0701");
  script_osvdb_id(72763, 72764, 72765);
  script_xref(name:"FEDORA", value:"2011-3746");

  script_name(english:"Fedora 14 : wordpress-3.1-1.fc14 (2011-3746)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In order to protect against two CVEs*, I'm upgrading Wordpress in all
releases to 3.1. In addition, this will obsolete wordpress-mu, since
this functionality has been migrated to the main wordpress release as
of wordpress 3.0, and wordpress-mu has been deprecated upstream. I
would not normally make so drastic a change on any stable release,
especially EPEL, but backporting patches to the 2.x series is becoming
increasingly unmaintainable. This is already done for rawhide and F15,
and I intend to build for F13, F14, EL5 and EL6 today, and send them
to testing, and then push to stable one the appropriate period has
elapsed.

Please redistribute this to anyone you know who might be affected and
may not be on this list.

Thank you, Jon

* https://bugzilla.redhat.com/show_bug.cgi?id=687909
https://bugzilla.redhat.com/show_bug.cgi?id=687911

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=687909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=687911"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/057003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04b3791f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/30");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"wordpress-3.1-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
