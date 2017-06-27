#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60428);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-1951");

  script_name(english:"Scientific Linux Security Update : sblim on SL4.x, SL5.x i386/x86_64");
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
"It was discovered that certain sblim libraries had an RPATH (runtime
library search path) set in the ELF (Executable and Linking Format)
header. This RPATH pointed to a sub-directory of a world-writable,
temporary directory. A local user could create a file with the same
name as a library required by sblim (such as libc.so) and place it in
the directory defined in the RPATH. This file could then execute
arbitrary code with the privileges of the user running an application
that used sblim (eg tog-pegasus). (CVE-2008-1951)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0806&L=scientific-linux-errata&T=0&P=2266
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?418d3b6c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"sblim-cmpi-base-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-base-devel-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-base-test-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-devel-1.0.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-fsvol-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-fsvol-test-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-network-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-network-devel-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-network-test-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-nfsv3-1.0.13-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-nfsv4-1.0.11-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-params-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-params-test-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-sysfs-1.1.8-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-sysfs-test-1.1.8-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-syslog-0.7.9-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-cmpi-syslog-test-0.7.9-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-gather-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-gather-devel-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-gather-provider-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-gather-test-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-testsuite-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"sblim-wbemcli-1.5.1-13a.el4_6.1")) flag++;

if (rpm_check(release:"SL5", reference:"sblim-cim-client-1.3.3-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cim-client-javadoc-1-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cim-client-manual-1-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-base-1.5.5-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-base-devel-1.5.5-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-base-test-1.5.5-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-devel-1.0.4-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-dns-0.5.2-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-dns-devel-1-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-dns-test-1-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-fsvol-1.4.4-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-fsvol-devel-1.4.4-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-fsvol-test-1.4.4-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-network-1.3.8-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-network-devel-1.3.8-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-network-test-1.3.8-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-nfsv3-1.0.14-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-nfsv3-test-1.0.14-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-nfsv4-1.0.12-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-nfsv4-test-1.0.12-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-params-1.2.6-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-params-test-1.2.6-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-samba-0.5.2-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-samba-devel-1-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-samba-test-1-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-sysfs-1.1.9-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-sysfs-test-1.1.9-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-syslog-0.7.11-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-cmpi-syslog-test-0.7.11-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-gather-2.1.2-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-gather-devel-2.1.2-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-gather-provider-2.1.2-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-gather-test-2.1.2-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-testsuite-1.2.4-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-tools-libra-0.2.3-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-tools-libra-devel-0.2.3-31.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"sblim-wbemcli-1.5.1-31.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
