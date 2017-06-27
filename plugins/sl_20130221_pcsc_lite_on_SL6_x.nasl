#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64956);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2010-4531");

  script_name(english:"Scientific Linux Security Update : pcsc-lite on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack-based buffer overflow flaw was found in the way pcsc-lite
decoded certain attribute values of Answer-to-Reset (ATR) messages. A
local attacker could use this flaw to execute arbitrary code with the
privileges of the user running the pcscd daemon (root, by default), by
inserting a specially crafted smart card. (CVE-2010-4531)

This update also fixes the following bugs :

  - Due to an error in the init script, the chkconfig
    utility did not automatically place the pcscd init
    script after the start of the HAL daemon. Consequently,
    the pcscd service did not start automatically at boot
    time. With this update, the pcscd init script has been
    changed to explicitly start only after HAL is up, thus
    fixing this bug.

  - Because the chkconfig settings and the startup files in
    the /etc/rc.d/ directory were not changed during the
    update described in the SLBA-2012:0990 advisory, the
    user had to update the chkconfig settings manually to
    fix the problem. Now, the chkconfig settings and the
    startup files in the /etc/rc.d/ directory are
    automatically updated as expected.

  - Previously, the SCardGetAttrib() function did not work
    properly and always returned the
    'SCARD_E_INSUFFICIENT_BUFFER' error regardless of the
    actual buffer size. This update applies a patch to fix
    this bug and the SCardGetAttrib() function now works as
    expected.

After installing this update, the pcscd daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=5528
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8660eff"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"pcsc-lite-1.5.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pcsc-lite-debuginfo-1.5.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pcsc-lite-devel-1.5.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pcsc-lite-doc-1.5.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pcsc-lite-libs-1.5.2-11.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
