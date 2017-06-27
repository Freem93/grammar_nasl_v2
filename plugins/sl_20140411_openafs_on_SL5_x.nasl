#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(73454);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/16 10:43:49 $");

  script_cve_id("CVE-2014-0159");

  script_name(english:"Scientific Linux Security Update : openafs on SL5.x, SL6.x i386/x86_64");
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
"An attacker with the ability to connect to an OpenAFS fileserver can
trigger a buffer overflow, crashing the server.

The GetStatistics64 remote procedure call (RPC) was introduced in
OpenAFS 1.4.8 as part of the support for fileserver partitions larger
than 2 TiB. The GetStatistics64 RPC is used by remote administrative
programs to retrieve statistical information about fileservers. The
GetStatistics64 RPC requests do not require authentication.

A bug has been discovered in the GetStatistics64 RPC which can trigger
a fileserver crash. The version argument of the GetStatistics64 RPC is
used to determine how much memory is allocated for the RPC reply.
However the range of this argument is not validated, allowing an
attacker to cause insufficient memory to be allocated for the
statistical information reply buffer.

Clients are not affected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1404&L=scientific-linux-errata&T=0&P=813
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a1e2f60"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.21.1.el5-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-348.21.1.el5PAE-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.21.1.el5xen-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.15-84.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.15-84.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"kmod-openafs-431-1.6.5.1-148.sl6.431.11.2")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.5.1-148.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.5.1-148.sl6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
