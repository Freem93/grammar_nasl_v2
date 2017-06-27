#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0035.
#

include("compat.inc");

if (description)
{
  script_id(79550);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-5519", "CVE-2014-2856", "CVE-2014-3537", "CVE-2014-5029", "CVE-2014-5030", "CVE-2014-5031");
  script_bugtraq_id(56494, 66788, 68788, 68842, 68846, 68847);
  script_osvdb_id(109070);

  script_name(english:"OracleVM 3.3 : cups (OVMSA-2014-0035)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Revert change to whitelist /rss/ resources, as this was
    not used upstream.

  - More STR #4461 fixes from upstream: make rss feeds
    world-readable, but cachedir private.

  - Fix icon display in web interface during server restart
    (STR #4475).

  - Fixes for upstream patch for STR #4461: allow /rss/
    requests for files we created.

  - Use upstream patch for STR #4461.

  - Applied upstream patch to fix CVE-2014-5029 (bug
    #1122600), CVE-2014-5030 (bug #1128764), CVE-2014-5031
    (bug #1128767).

  - Fix conf/log file reading for authenticated users (STR
    #4461).

  - Fix CGI handling (STR #4454, bug #1120419).

  - fix patch for CVE-2014-3537 (bug #1117794)

  - CVE-2014-2856: cross-site scripting flaw (bug #1117798)

  - CVE-2014-3537: insufficient checking leads to privilege
    escalation (bug #1117794)

  - Removed package description changes.

  - Applied patch to fix 'Bad request' errors as a result of
    adding in httpSetTimeout (STR #4440, also part of svn
    revision 9967).

  - Fixed timeout issue with cupsd reading when there is no
    data ready (bug #1110045).

  - Fixed synconclose patch to avoid 'too many arguments for
    format' warning.

  - Fixed settimeout patch to include math.h for fmod
    declaration.

  - Fixed typo preventing web interface from changing driver
    (bug #1104483, STR #3601).

  - Fixed SyncOnClose patch (bug #984883).

  - Use upstream patch to avoid replaying GSS credentials
    (bug #1040293).

  - Prevent BrowsePoll problems across suspend/resume (bug
    #769292) :

  - Eliminate indefinite wait for response (svn revision
    9688).

  - Backported httpSetTimeout API function from CUPS 1.5 and
    use it in the ipp backend so that we wait indefinitely
    until the printer responds, we get a hard error, or the
    job is cancelled.

  - cups-polld: reconnect on error.

  - Added new SyncOnClose directive to use fsync after
    altering configuration files: defaults to 'Yes'. Adjust
    in cupsd.conf (bug #984883).

  - Fix cupsctl man page typo (bug #1011076).

  - Use more portable rpm specfile syntax for conditional
    php building (bug #988598).

  - Fix SetEnv directive in cupsd.conf (bug #986495).

  - Fix 'collection' attribute sending (bug #978387).

  - Prevent format_log segfault (bug #971079).

  - Prevent stringpool corruption (bug #884851).

  - Don't crash when job queued for printer that times out
    (bug #855431).

  - Upstream patch for broken multipart handling (bug
    #852846).

  - Install /etc/cron.daily/cups with correct permissions
    (bug #1012482).

  - Fixes for jobs with multiple files and multiple formats
    (bug #972242).

  - Applied patch to fix CVE-2012-5519 (privilege escalation
    for users in SystemGroup or with equivalent polkit
    permission). This prevents HTTP PUT requests with paths
    under /admin/conf/ other than that for cupsd.conf, and
    also prevents such requests altering certain
    configuration directives such as PageLog and FileDevice
    (bug #875898)."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-November/000235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c27127c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups / cups-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"cups-1.4.2-67.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"cups-libs-1.4.2-67.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-libs");
}
