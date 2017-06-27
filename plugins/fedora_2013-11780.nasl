#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-11780.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68999);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/19 21:02:57 $");

  script_cve_id("CVE-2013-4116");
  script_bugtraq_id(61083);
  script_xref(name:"FEDORA", value:"2013-11780");

  script_name(english:"Fedora 18 : nodejs-normalize-package-data-0.2.0-1.fc18 / node-gyp-0.10.6-1.fc18 / etc (2013-11780)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides the latest npm and updates its dependencies. It
also fixes a minor security bug.

For more information about recent changes in npm, see the changelog at
GitHub: https://github.com/isaacs/npm/commits/v1.3.3

Additionally, this update restricts all included packages to only the
architectures supported by the V8 JavaScript runtime.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=921649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=927575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=948659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=953051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=954280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=954281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=968919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=973968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=976984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=983918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=984202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=985305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/isaacs/npm/commits/v1.3.3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4e8aeb8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27860245"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a10c181"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0880609c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?380f04a8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6f978c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b883b6ca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eedc3937"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?666e422f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae21bffa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?729dac04"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de74e9bd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0849f1c4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77cc1ea6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8573e9fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112130.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1289a3cb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a49b6103"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98b7bfa4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2338c216"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f663137"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efd714a3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cca3a991"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?909902ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbccf294"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112139.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?488df08b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?404d2626"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d23ae24d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8138075"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49750b8e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3488e88a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bd590ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b1120a7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55adbc9d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73ab8d5f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cd5d058"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3dc211c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e5afd8e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fb7601b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112153.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b48814bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e3e7c03"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80da6dc1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c61fddc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?166cb418"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25f56e08"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e26cadcb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2be6707a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112161.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d07ba1f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cf9badd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?116f3c94"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:node-gyp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-aws-sign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-better-assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-boom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-callsite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-child-process-close");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-cmd-shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-config-chain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-cookie-jar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-couch-login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-cryptiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-forever-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-form-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-fstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-fstream-ignore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-fstream-npm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-github-url-from-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-graceful-fs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-hawk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-hoek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-http-signature");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-inherits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-inherits1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-init-package-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-json-stringify-safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-lockfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-normalize-package-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-npm-registry-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-npm-user-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-npmconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-npmlog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-oauth-sign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-read-installed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-read-package-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-request");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-rimraf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-semver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-sha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-slide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-sntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-tap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-tunnel-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-vows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"node-gyp-0.10.6-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-ansi-0.2.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-asn1-0.1.11-3.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-aws-sign-0.3.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-better-assert-1.0.0-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-boom-0.4.2-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-callsite-1.0.0-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-child-process-close-0.1.1-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-cmd-shim-1.1.0-3.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-config-chain-1.1.7-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-cookie-jar-0.3.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-couch-login-0.1.17-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-cryptiles-0.2.1-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-ctype-0.5.3-3.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-editor-0.0.4-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-forever-agent-0.5.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-form-data-0.0.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-fstream-0.1.23-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-fstream-ignore-0.0.7-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-fstream-npm-0.1.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-github-url-from-git-1.1.1-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-glob-3.2.3-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-graceful-fs-2.0.0-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-hawk-0.15.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-hoek-0.9.1-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-http-signature-0.10.0-3.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-inherits-2.0.0-3.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-inherits1-1.0.0-11.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-init-package-json-0.0.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-json-stringify-safe-5.0.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-lockfile-0.4.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-normalize-package-data-0.2.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-npm-registry-client-0.2.27-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-npm-user-validate-0.0.3-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-npmconf-0.1.1-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-npmlog-0.0.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-oauth-sign-0.3.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-read-installed-0.2.2-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-read-package-json-1.1.0-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-request-2.21.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-rimraf-2.2.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-semver-2.0.10-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-sha-1.0.1-4.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-slide-1.1.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-sntp-0.2.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-tap-0.4.1-6.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-tunnel-agent-0.3.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nodejs-vows-0.7.0-6.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"npm-1.3.3-1.fc18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "node-gyp / nodejs-ansi / nodejs-asn1 / nodejs-aws-sign / etc");
}
