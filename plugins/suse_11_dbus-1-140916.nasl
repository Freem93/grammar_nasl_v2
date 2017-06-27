#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77755);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/23 14:22:41 $");

  script_cve_id("CVE-2014-3638", "CVE-2014-3639");

  script_name(english:"SuSE 11.3 Security Update : dbus-1 (SAT Patch Number 9733)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various denial of service issues were fixed in the DBUS service.

  - dbus-daemon tracks whether method call messages expect a
    reply, so that unsolicited replies can be dropped. As
    currently implemented, if there are n parallel method
    calls in progress, each method reply takes O(n) CPU
    time. A malicious user could exploit this by opening the
    maximum allowed number of parallel connections and
    sending the maximum number of parallel method calls on
    each one, causing subsequent method calls to be
    unreasonably slow, a denial of service. (CVE-2014-3638)

  - dbus-daemon allows a small number of 'incomplete'
    connections (64 by default) whose identity has not yet
    been confirmed. When this limit has been reached,
    subsequent connections are dropped. Alban's testing
    indicates that one malicious process that makes repeated
    connection attempts, but never completes the
    authentication handshake and instead waits for
    dbus-daemon to time out and disconnect it, can cause the
    majority of legitimate connection attempts to fail.
    (CVE-2014-3639)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3638.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3639.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9733.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"dbus-1-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"dbus-1-x11-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"dbus-1-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"dbus-1-32bit-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"dbus-1-x11-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"dbus-1-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"dbus-1-x11-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"dbus-1-32bit-1.2.10-3.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"dbus-1-32bit-1.2.10-3.31.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
