#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(86671);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/10 15:23:00 $");

  script_cve_id("CVE-2015-7762", "CVE-2015-7763");

  script_name(english:"Scientific Linux Security Update : openafs on SL5.x, SL6.x, SL7.x i386/x86_64");
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
"This release fixes the high impact security vulnerability named
'Tattletale'

The packet paylod of Rx ACK packets is not fully initialized, leaking
plaintext from packets previously processed."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1510&L=scientific-linux-errata&F=&S=&P=6806
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d31d180"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-406.el5-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-406.el5PAE-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-406.el5xen-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.15-88.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.15-88.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"kmod-openafs-573-1.6.14-219.sl6.573.3.1")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.14-219.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.14-219.sl6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-229-1.6.14-219.sl7.229.14.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-devel-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-client-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-compat-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-devel-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kernel-source-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kpasswd-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-krb5-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-module-tools-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-plumbing-tools-1.6.14-219.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-server-1.6.14-219.sl7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
