#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0469-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83578);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2007-6750", "CVE-2011-1473", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-3639", "CVE-2011-4317", "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053", "CVE-2012-0883", "CVE-2012-2687", "CVE-2012-4557");
  script_bugtraq_id(21865, 48626, 49957, 50494, 50802, 51705, 51869, 53046, 55131, 56753);
  script_osvdb_id(76079, 76744, 84818, 121361);

  script_name(english:"SUSE SLES10 Security Update : apache2 (SUSE-SU-2013:0469-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Apache2 LTSS roll-up update for SUSE Linux Enterprise 10 SP3 LTSS
fixes the following security issues and bugs :

  - CVE-2012-4557: Denial of Service via special requests in
    mod_proxy_ajp

  - CVE-2012-0883: improper LD_LIBRARY_PATH handling

  - CVE-2012-2687: filename escaping problem

  - CVE-2012-0031: Fixed a scoreboard corruption (shared mem
    segment) by child causes crash of privileged parent
    (invalid free()) during shutdown.

  - CVE-2012-0053: Fixed an issue in error responses that
    could expose 'httpOnly' cookies when no custom
    ErrorDocument is specified for status code 400'.

  - The SSL configuration template has been adjusted not to
    suggested weak ciphers CVE-2007-6750: The
    'mod_reqtimeout' module was backported from Apache
    2.2.21 to help mitigate the 'Slowloris' Denial of
    Service attack.

    You need to enable the 'mod_reqtimeout' module in your
    existing apache configuration to make it effective, e.g.
    in the APACHE_MODULES line in /etc/sysconfig/apache2.

  - CVE-2011-3639, CVE-2011-3368, CVE-2011-4317: This update
    also includes several fixes for a mod_proxy reverse
    exposure via RewriteRule or ProxyPassMatch directives.

  - CVE-2011-1473: Fixed the SSL renegotiation DoS by
    disabling renegotiation by default.

  - CVE-2011-3607: Integer overflow in ap_pregsub function
    resulting in a heap-based buffer overflow could
    potentially allow local attackers to gain privileges

Additionally, some non-security bugs have been fixed which are listed
in the changelog file.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=25e42b7bd84d54954a51c9fe38e777e0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?216a63aa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0883.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/688472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/719236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/722545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/727071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/727993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/729181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/736706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/738855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/741243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/743743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/757710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/777260"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130469-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64e1fdd5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-2.2.3-16.32.45.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-devel-2.2.3-16.32.45.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-doc-2.2.3-16.32.45.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-example-pages-2.2.3-16.32.45.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-prefork-2.2.3-16.32.45.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-worker-2.2.3-16.32.45.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2");
}
