#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-19512.
#

include("compat.inc");

if (description)
{
  script_id(70820);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 21:37:39 $");

  script_cve_id("CVE-2013-4450");
  script_bugtraq_id(63229);
  script_xref(name:"FEDORA", value:"2013-19512");

  script_name(english:"Fedora 20 : libuv-0.10.18-1.fc20 / nodejs-0.10.21-1.fc20 (2013-19512)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release contains a security fix for the http server
implementation, please upgrade as soon as possible. For more
information, see <http://ur1.ca/fwrj8>.

2013.10.18, node.js Version 0.10.21 (Stable)

  - crypto: clear errors from verify failure (Timothy J
    Fontaine)

  - dtrace: interpret two byte strings (Dave Pacheco)

  - fs: fix fs.truncate() file content zeroing bug (Ben
    Noordhuis)

  - http: provide backpressure for pipeline flood (isaacs)

  - tls: fix premature connection termination (Ben
    Noordhuis)

2013.10.19, libuv Version 0.10.18 (Stable)

  - unix: fix uv_spawn() NULL pointer deref on ENOMEM (Ben
    Noordhuis)

  - unix: don't close inherited fds on uv_spawn() fail (Ben
    Noordhuis)

  - unix: revert recent FSEvent changes (Ben Noordhuis)

  - unix: fix non-synchronized access in signal.c (Ben
    Noordhuis)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ur1.ca/fwrj8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1021170"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-November/121092.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b432c6b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-November/121093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07711c7d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuv and / or nodejs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libuv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"libuv-0.10.18-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"nodejs-0.10.21-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libuv / nodejs");
}
