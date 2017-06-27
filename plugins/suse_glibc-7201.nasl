#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50377);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-1391", "CVE-2010-0015", "CVE-2010-0296", "CVE-2010-0830", "CVE-2010-3847", "CVE-2010-3856");

  script_name(english:"SuSE 10 Security Update : glibc (ZYPP Patch Number 7201)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues were fixed :

  - Decoding of the $ORIGIN special value in various LD_
    environment variables allowed local attackers to execute
    code in context of e.g. setuid root programs, elevating
    privileges. This issue does not affect SUSE as an
    assertion triggers before the respective code is
    executed. The bug was fixed nevertheless.
    (CVE-2010-3847)

  - The LD_AUDIT environment was not pruned during setuid
    root execution and could load shared libraries from
    standard system library paths. This could be used by
    local attackers to inject code into setuid root programs
    and so elevated privileges. (CVE-2010-3856)

  - Integer overflow causing arbitrary code execution in
    ld.so --verify mode could be induced by a specially
    crafted binary. (CVE-2010-0830)

  - The addmntent() function would not escape the newline
    character properly, allowing the user to insert
    arbitrary newlines to the /etc/mtab; if the addmntent()
    is run by a setuid mount binary that does not do extra
    input checking, this would allow custom entries to be
    inserted in /etc/mtab. (CVE-2010-0296)

  - The strfmon() function contains an integer overflow
    vulnerability in width specifiers handling that could be
    triggered by an attacker that can control the format
    string passed to strfmon(). (CVE-2008-1391)

  - Some setups (mainly Solaris-based legacy setups) include
    shadow information (password hashes) as so-called
    'adjunct passwd' table, mangling it with the rest of
    passwd columns instead of keeping it in the shadow
    table. Normally, Solaris will disclose this information
    only to clients bound to a priviledged port, but when
    nscd is deployed on the client, getpwnam() would
    disclose the password hashes to all users. New mode
    'adjunct as shadow' can now be enabled in
    /etc/default/nss that will move the password hashes from
    the world-readable passwd table to emulated shadow table
    (that is not cached by nscd). (CVE-2010-0015)

Some invalid behavior, crashes and memory leaks were fixed :

  - nscd in the paranoia mode would crash on the periodic
    restart in case one of the databases was disabled in the
    nscd configuration.

  - When closing a widechar stdio stream, memory would
    sometimes be leaked.

  - memcpy() on power6 would errorneously use a 64-bit
    instruction within 32-bit code in certain corner cases.

  - jrand48() returns numbers in the wrong range on 64-bit
    systems: Instead of [-231, +231), the value was always
    positive and sometimes higher than the supposed upper
    bound.

  - Roughly every 300 days of uptime, the times() function
    would report an error for 4096 seconds, a side-effect of
    how system calls are implemented on i386. glibc was
    changed to never report an error and crash an
    application that would trigger EFAULT by kernel (because
    of invalid pointer passed to the times() syscall)
    before.

  - getifaddrs() would report infiniband interfaces with
    corrupted ifa_name structure field.

  - getgroups(-1) normally handles the invalid array size
    gracefully by setting EINVAL. However, a crash would be
    triggered in case the code was compiled using
    '-DFORTIFYSOURCE=2 -O2'.

  - Pthread cleanup handlers would not always be invoked on
    thread cancellation (e.g. in RPC code, but also in other
    parts of glibc that may hang outside of a syscall) -
    glibc is now compiled with

    -fasynchronous-unwind-tables. Some other minor issues
    were fixed :

  - There was a problem with sprof<->dlopen() interaction
    due to a missing flag in the internal dlopen() wrapper.

  - On x86_64, backtrace of a static destructor would stop
    in the _fini() glibc pseudo-routine, making it difficult
    to find out what originally triggered the program
    termination. The routine now has unwind information
    attached.

  - glibc-locale now better coexists with sap-locale on
    upgrades by regenerating the locale/gconv indexes
    properly."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1391.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3856.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7201.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(189, 255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, reference:"glibc-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"glibc-devel-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"glibc-html-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"glibc-i18ndata-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"glibc-info-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"glibc-locale-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"nscd-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"glibc-32bit-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"glibc-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"glibc-devel-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"glibc-html-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"glibc-i18ndata-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"glibc-info-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"glibc-locale-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"glibc-profile-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"nscd-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"glibc-32bit-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.77.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"glibc-profile-32bit-2.4-31.77.76.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
