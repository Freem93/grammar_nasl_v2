#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0974-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83945);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/07/18 15:54:02 $");

  script_cve_id("CVE-2013-5704", "CVE-2014-3581", "CVE-2014-8109", "CVE-2015-0228");
  script_bugtraq_id(66550, 71656, 73040, 73041);
  script_osvdb_id(105190, 112168, 115375, 119066);

  script_name(english:"SUSE SLES12 Security Update : apache2 (SUSE-SU-2015:0974-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache2 updated to fix four security issues and one non-security bug.

The following vulnerabilities have been fixed :

  - mod_headers rules could be bypassed via chunked
    requests. Adds 'MergeTrailers' directive to restore
    legacy behavior. (bsc#871310, CVE-2013-5704)

  - An empty value in Content-Type could lead to a crash
    through a null pointer dereference and a denial of
    service. (bsc#899836, CVE-2014-3581)

  - Remote attackers could bypass intended access
    restrictions in mod_lua LuaAuthzProvider when multiple
    Require directives with different arguments are used.
    (bsc#909715, CVE-2014-8109)

  - Remote attackers could cause a denial of service
    (child-process crash) by sending a crafted WebSocket
    Ping frame after a Lua script has called the wsupgrade
    function. (bsc#918352, CVE-2015-0228)

The following non-security issues have been fixed :

  - The Apache2 systemd service file was changed to fix
    situation where apache wouldn't start at boot when using
    an encrypted certificate because the user wasn't
    prompted for password during boot. (bsc#792309)

Additionally, mod_imagemap is now included by default in the package.
(bsc#923090)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/792309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/871310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-5704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3581.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0228.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150974-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79aea48c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-226=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-226=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-debuginfo-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-debugsource-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-example-pages-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-prefork-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-prefork-debuginfo-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-utils-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-utils-debuginfo-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-worker-2.4.10-12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-worker-debuginfo-2.4.10-12.1")) flag++;


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
