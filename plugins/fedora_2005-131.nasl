#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-131.
#

include("compat.inc");

if (description)
{
  script_id(62253);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/21 21:38:04 $");

  script_xref(name:"FEDORA", value:"2005-131");

  script_name(english:"Fedora Core 2 : mailman-2.1.5-8.fc2 (2005-131)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is a critical security flaw in Mailman 2.1.5 which will allow
attackers to read arbitrary files.

The extent of the vulnerability depends on what version of Apache
(httpd) you are running, and (possibly) how you have configured your
web server. It is believed the vulnerability is not available when
Mailman is paired with a version of Apache >= 2.0, however earlier
versions of Apache, e.g. version 1.3, will allow the exploit when
executing a Mailman CGI script. All versions of Fedora have shipped
with the later 2.0 version of Apache and thus if you are running a
Fedora release you are not likely to be vulnerable to the exploit
unless you have explicitly downgraded the version of your web server.
However, installing this version of mailman with a security patch
represents a prudent safeguard.

This issue has been assigned CVE number CVE-2005-0202.

The bug report associated with this is:
https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=147343

The errata associated with this for RHEL releases is:
http://rhn.redhat.com/errata/RHSA-2005-136.html

For additional peace of mind, it is recommended that you regenerate
your list member passwords. Instructions on how to do this, and more
information about this vulnerability are available here :

http://www.list.org/security.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.list.org/security.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=147343"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-February/000695.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c53d15b9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman and / or mailman-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"mailman-2.1.5-8.fc2")) flag++;
if (rpm_check(release:"FC2", reference:"mailman-debuginfo-2.1.5-8.fc2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo");
}
