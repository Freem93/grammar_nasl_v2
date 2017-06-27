#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-15839.
#

include("compat.inc");

if (description)
{
  script_id(56963);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 21:56:29 $");

  script_cve_id("CVE-2011-4129");
  script_bugtraq_id(50817);
  script_xref(name:"FEDORA", value:"2011-15839");

  script_name(english:"Fedora 15 : libsocialweb-0.25.20-1.fc15 / rest-0.7.12-1.fc15 (2011-15839)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2011-4129

A security flaw was found in the way the libsocialweb, a social
network data aggregator, performed its initialization when this
service start was initiated by the dbus daemon. Due to a deficiency in
a way the libsocialweb service was initialized, an untrusted (non-SSL)
network connection has been opened to remote Twitter service servers
without explicit approval of the user, running the libsocialweb
service on the local host. A remote attacker could use this flaw to
conduct various MITM attacks and potentially alter integrity of the
user account in question.

  - libsocialweb: The views will try and fetch content from
    the web service even if they aren't configured.

  - rest: enforce that the SSL certificate is valid

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=752022"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-November/070086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc54c23f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-November/070087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e416fbe5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsocialweb and / or rest packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libsocialweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/29");
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
if (rpm_check(release:"FC15", reference:"libsocialweb-0.25.20-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"rest-0.7.12-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsocialweb / rest");
}
