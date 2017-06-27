#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-11666.
#

include("compat.inc");

if (description)
{
  script_id(42846);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 22:32:49 $");

  script_cve_id("CVE-2009-3639");
  script_bugtraq_id(36804);
  script_xref(name:"FEDORA", value:"2009-11666");

  script_name(english:"Fedora 10 : proftpd-1.3.2b-1.fc10 (2009-11666)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes CVE-2009-3639, in which proftpd's mod_tls, when the
dNSNameRequired TLS option is enabled, does not properly handle a '\0'
character in a domain name in the Subject Alternative Name field of an
X.509 client certificate. This allows remote attackers to bypass
intended client-hostname restrictions via a crafted certificate issued
by a legitimate Certification Authority. This update to upstream
release 1.3.2b also fixes the following issues recorded in the proftpd
bug tracker at bugs.proftpd.org: - Regression causing command-line
define options not to work (bug 3221) - Use correct cached user values
with 'SQLNegativeCache on' (bug 3282) - Slower transfers of multiple
small files (bug 3284) - Support MaxTransfersPerHost,
MaxTransfersPerUser properly (bug 3287) - Handle symlinks to
directories with trailing slashes properly (bug 3297)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530719"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/031145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6cb50a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"proftpd-1.3.2b-1.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd");
}
