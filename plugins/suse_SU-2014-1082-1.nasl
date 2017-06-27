#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1082-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83632);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2013-1862", "CVE-2013-1896", "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-0226", "CVE-2014-0231");
  script_bugtraq_id(59826, 61129, 66303, 68678, 68742);
  script_osvdb_id(93366, 95498, 104579, 104580, 109216, 109234);

  script_name(english:"SUSE SLES10 Security Update : apache2 (SUSE-SU-2014:1082-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This apache2 update fixes the following security issues :

  - log_cookie mod_log_config.c remote denial of service
    (CVE-2014-0098, bnc#869106)

  - mod_dav denial of service (CVE-2013-6438, bnc#869105)

  - mod_cgid denial of service (CVE-2014-0231, bnc#887768)

  - mod_status heap-based buffer overflow (CVE-2014-0226,
    bnc#887765)

  - mod_rewrite: escape logdata to avoid terminal escapes
    (CVE-2013-1862, bnc#829057)

  - mod_dav: segfault in merge request (CVE-2013-1896,
    bnc#829056)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=0593c1f59d8a810c00150b05cea3af2f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d206084"
  );
  # http://download.suse.com/patch/finder/?keywords=0ddc907bde6fcbad1e94944d867f60dd
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0348c3ed"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0226.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/829056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/829057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/869105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/869106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/887765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/887768"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141082-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59a14554"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
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
if (os_ver == "SLES10" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", reference:"apache2-2.2.3-16.50.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"apache2-devel-2.2.3-16.50.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"apache2-doc-2.2.3-16.50.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"apache2-example-pages-2.2.3-16.50.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"apache2-prefork-2.2.3-16.50.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"apache2-worker-2.2.3-16.50.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-2.2.3-16.32.51.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-devel-2.2.3-16.32.51.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-doc-2.2.3-16.32.51.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-example-pages-2.2.3-16.32.51.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-prefork-2.2.3-16.32.51.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"apache2-worker-2.2.3-16.32.51.2")) flag++;


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
