#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85150);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/08/13 13:44:24 $");

  script_cve_id("CVE-2015-3282", "CVE-2015-3283", "CVE-2015-3284", "CVE-2015-3285");

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
"All server platforms

* Fix for CVE-2015-3282: vos leaks stack data onto the wire in the
clear when creating vldb entries

* Workaround for CVE-2015-3283: bos commands can be spoofed,
including some which alter server state

* Disabled searching the VLDB by volume name regular
expression to avoid possible buffer overruns in the volume
location server

All client platforms

* Fix for CVE-2015-3284: pioctls leak kernel memory

* Fix for CVE-2015-3285: kernel pioctl support for OSD
command passing can trigger a panic

After installing the update, you must restart your AFS connections and
AFS services."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1507&L=scientific-linux-errata&F=&S=&P=13603
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d1b1f26"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
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
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-404.el5-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-404.el5PAE-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-404.el5xen-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-406.el5-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-406.el5PAE-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-406.el5xen-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.15-86.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.15-86.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"kmod-openafs-504-1.6.13-215.sl6.504")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.13-215.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.13-215.sl6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-229-1.6.13-215.sl7.229.1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-devel-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-client-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-compat-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-devel-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kernel-source-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kpasswd-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-krb5-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-module-tools-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-plumbing-tools-1.6.13-215.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-server-1.6.13-215.sl7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
