#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2090-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93295);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/16 16:05:34 $");

  script_cve_id("CVE-2016-5387");
  script_osvdb_id(141669);
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"SUSE SLES12 Security Update : apache2 (SUSE-SU-2016:2090-1) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apache2 fixes the following issues :

  - It used to be possible to set an arbitrary $HTTP_PROXY
    environment variable for request handlers -- like CGI
    scripts -- by including a specially crafted HTTP header
    in the request (CVE-2016-5387). As a result, these
    server components would potentially direct all their
    outgoing HTTP traffic through a malicious proxy server.
    This patch fixes the issue: the updated Apache server
    ignores such HTTP headers and never sets $HTTP_PROXY for
    sub-processes (unless a value has been explicitly
    configured by the administrator in the configuration
    file). (bsc#988488)

  - Ignore SIGINT signal in child processes. This fixes a
    race condition in signals handling when httpd is running
    on foreground and the user hits ctrl+c. (bsc#970391)

  - Don't put the backend in error state (by default) when
    500/503 is overridden. (bsc#951692)

  - Remove obsolete /usr/share/apache2/rc.apache2 sample
    script. (bsc#973381)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5387.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162090-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6767d88"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2016-1235=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2016-1235=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-debuginfo-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-debugsource-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-example-pages-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-prefork-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-prefork-debuginfo-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-utils-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-utils-debuginfo-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-worker-2.4.10-14.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-worker-debuginfo-2.4.10-14.17.1")) flag++;


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
