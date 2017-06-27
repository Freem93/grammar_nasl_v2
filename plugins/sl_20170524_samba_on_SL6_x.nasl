#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(100403);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_cve_id("CVE-2017-7494");

  script_name(english:"Scientific Linux Security Update : samba on SL6.x, SL7.x i386/x86_64");
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
"Security Fix(es) :

  - A remote code execution flaw was found in Samba. A
    malicious authenticated samba client, having write
    access to the samba share, could use this flaw to
    execute arbitrary code as root. (CVE-2017-7494)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1705&L=scientific-linux-errata&F=&S=&P=7563
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76f7ef4d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libsmbclient-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"libsmbclient-devel-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-client-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-common-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-debuginfo-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-doc-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-domainjoin-gui-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"samba-glusterfs-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-swat-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-clients-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-devel-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-krb5-locator-3.6.23-43.el6_9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-devel-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-devel-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"samba-common-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-tools-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-debuginfo-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-devel-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-krb5-printing-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"samba-pidl-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-python-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-clients-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-modules-4.4.4-14.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
