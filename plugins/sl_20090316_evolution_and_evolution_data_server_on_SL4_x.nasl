#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60544);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");

  script_name(english:"Scientific Linux Security Update : evolution and evolution-data-server on SL4.x i386/x86_64");
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
"Evolution Data Server provides a unified back-end for applications
which interact with contacts, task and calendar information. Evolution
Data Server was originally developed as a back-end for Evolution, but
is now used by multiple other applications.

Evolution did not properly check the Secure/Multipurpose Internet Mail
Extensions (S/MIME) signatures used for public key encryption and
signing of e-mail messages. An attacker could use this flaw to spoof a
signature by modifying the text of the e-mail message displayed to the
user. (CVE-2009-0547)

It was discovered that evolution did not properly validate NTLM (NT
LAN Manager) authentication challenge packets. A malicious server
using NTLM authentication could cause evolution to disclose portions
of its memory or crash during user authentication. (CVE-2009-0582)

Multiple integer overflow flaws which could cause heap-based buffer
overflows were found in the Base64 encoding routines used by evolution
and evolution-data-server. This could cause evolution, or an
application using evolution-data-server, to crash, or, possibly,
execute an arbitrary code when large untrusted data blocks were
Base64-encoded. (CVE-2009-0587)

All running instances of evolution and evolution-data-server must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0903&L=scientific-linux-errata&T=0&P=1569
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd2adf0f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"evolution-2.0.2-41.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"evolution-data-server-1.0.2-14.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"evolution-data-server-devel-1.0.2-14.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"evolution-devel-2.0.2-41.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"evolution28-evolution-data-server-1.8.0-37.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"evolution28-evolution-data-server-devel-1.8.0-37.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"evolution28-libsoup-2.2.98-5.el4.1")) flag++;
if (rpm_check(release:"SL4", reference:"evolution28-libsoup-devel-2.2.98-5.el4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
