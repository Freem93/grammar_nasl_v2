#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-4532.
#

include("compat.inc");

if (description)
{
  script_id(29715);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_cve_id("CVE-2007-5964");
  script_bugtraq_id(26841);
  script_xref(name:"FEDORA", value:"2007-4532");

  script_name(english:"Fedora 8 : autofs-5.0.2-20 (2007-4532)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Dec 13 2007 Ian Kent <ikent at redhat.com> -
    5.0.2-20

    - Bug 409701: CVE-2007-5964 Privilege Escalation (from
      local system) through /net autofs mount configuration
      bug

    - use mount option 'nosuid' for '-hosts' map unless
      'suid' is explicily specified.

    - Tue Nov 20 2007 Ian Kent <ikent at redhat.com> -
      5.0.2-17

    - fix schema selection in LDAP schema discovery.

    - check for '*' when looking up wildcard in LDAP.

    - fix couple of edge case parse fails of timeout option.

    - add SEARCH_BASE configuration option.

    - add random selection as a master map entry option.

    - re-read config on HUP signal.

    - add LDAP_URI, LDAP_TIMEOUT and LDAP_NETWORK_TIMEOUT
      configuration options.

    - fix deadlock in submount mount module.

    - fix lack of ferror() checking when reading files.

    - fix typo in autofs(5) man page.

    - fix map entry expansion when undefined macro is
      present.

    - remove unused export validation code.

    - add dynamic logging (adapted from v4 patch from Jeff
      Moyer).

    - fix recursive loopback mounts (Matthias Koenig).

    - add map re-load to verbose logging.

    - fix handling of LDAP base dns with spaces.

    - handle MTAB_NOTUPDATED status return from mount.

    - when default master map, auto.master, is used also
      check for auto_master.

    - update negative mount timeout handling.

    - fix large group handling (Ryan Thomas).

    - fix for dynamic logging breaking non-sasl build
      (Guillaume Rousse).

    - eliminate NULL proc ping for singleton host or local
      mounts.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=409701"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006011.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ff4ec77"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs and / or autofs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:autofs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"autofs-5.0.2-20")) flag++;
if (rpm_check(release:"FC8", reference:"autofs-debuginfo-5.0.2-20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autofs / autofs-debuginfo");
}
