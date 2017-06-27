#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-13442.
#

include("compat.inc");

if (description)
{
  script_id(56397);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:56:28 $");

  script_bugtraq_id(49808, 49811, 49837, 49849, 49850);
  script_xref(name:"FEDORA", value:"2011-13442");

  script_name(english:"Fedora 15 : thunderbird-7.0-1.fc15 / thunderbird-lightning-1.0-0.50.b7.fc15 (2011-13442)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The latest version of Thunderbird has the following changes :

  - Fixed several security issues:
    http://www.mozilla.org/security/known-vulnerabilities/th
    underbird.html#thunderbird7

    - Numerous platform fixes that improve speed,
      performance and stability

The latest version of Firefox and Thunderbird has the following
changes :

  - Revoked the root certificate for DigiNotar due to
    fraudulent SSL certificate issuance (see bug
    mozbz#682927 and the security advisory)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird.html#thunderbird7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?725739c2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067374.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e77d173"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c60f60f9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-lightning
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/06");
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
if (rpm_check(release:"FC15", reference:"thunderbird-7.0-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"thunderbird-lightning-1.0-0.50.b7.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-lightning");
}
