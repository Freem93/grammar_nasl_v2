#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60373);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-5901", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947", "CVE-2008-0948");

  script_name(english:"Scientific Linux Security Update : krb5 on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A flaw was found in the way the MIT Kerberos Authentication Service
and Key Distribution Center server (krb5kdc) handled Kerberos v4
protocol packets. An unauthenticated remote attacker could use this
flaw to crash the krb5kdc daemon, disclose portions of its memory, or
possibly execute arbitrary code using malformed or truncated Kerberos
v4 protocol requests. (CVE-2008-0062, CVE-2008-0063)

This issue only affected krb5kdc with Kerberos v4 protocol
compatibility enabled, which is the default setting on Scientific
Linux 4. Kerberos v4 protocol support can be disabled by adding
'v4_mode=none' (without the quotes) to the '[kdcdefaults]' section of
/var/kerberos/krb5kdc/kdc.conf.

SL 3x only: A flaw was found in the RPC library used by the MIT
Kerberos kadmind server. An unauthenticated remote attacker could use
this flaw to crash kadmind. This issue only affected systems with
certain resource limits configured and did not affect systems using
default resource limits used by Scientific Linux 3. (CVE-2008-0948)

SL 4x and 5x only: Multiple memory management flaws were discovered in
the GSSAPI library used by MIT Kerberos. These flaws could possibly
result in use of already freed memory or an attempt to free already
freed memory blocks (double-free flaw), possibly causing a crash or
arbitrary code execution. (CVE-2007-5901, CVE-2007-5971)

SL 5x only: Jeff Altman of Secure Endpoints discovered a flaw in the
RPC library as used by MIT Kerberos kadmind server. An unauthenticated
remote attacker could use this flaw to crash kadmind or possibly
execute arbitrary code. This issue only affected systems with certain
resource limits configured and did not affect systems using default
resource limits used by Red Hat Enterprise Linux 5. (CVE-2008-0947)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0803&L=scientific-linux-errata&T=0&P=1691
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f79a562e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
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
if (rpm_check(release:"SL3", reference:"krb5-devel-1.2.7-68")) flag++;
if (rpm_check(release:"SL3", reference:"krb5-libs-1.2.7-68")) flag++;
if (rpm_check(release:"SL3", reference:"krb5-server-1.2.7-68")) flag++;
if (rpm_check(release:"SL3", reference:"krb5-workstation-1.2.7-68")) flag++;

if (rpm_check(release:"SL4", reference:"krb5-devel-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-libs-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-server-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-workstation-1.3.4-54.el4_6.1")) flag++;

if (rpm_check(release:"SL5", reference:"krb5-devel-1.6.1-17.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-libs-1.6.1-17.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-1.6.1-17.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-workstation-1.6.1-17.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
