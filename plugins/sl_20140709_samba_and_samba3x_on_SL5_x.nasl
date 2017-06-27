#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(76449);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/10 10:45:36 $");

  script_cve_id("CVE-2014-0244", "CVE-2014-3493");

  script_name(english:"Scientific Linux Security Update : samba and samba3x on SL5.x, SL6.x i386/srpm/x86_64");
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
"A denial of service flaw was found in the way the sys_recvfile()
function of nmbd, the NetBIOS message block daemon, processed
non-blocking sockets. An attacker could send a specially crafted
packet that, when processed, would cause nmbd to enter an infinite
loop and consume an excessive amount of CPU time. (CVE-2014-0244)

It was discovered that smbd, the Samba file server daemon, did not
properly handle certain files that were stored on the disk and used a
valid Unicode character in the file name. An attacker able to send an
authenticated non-Unicode request that attempted to read such a file
could cause smbd to crash. (CVE-2014-3493)

After installing this update, the smb service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1407&L=scientific-linux-errata&T=0&P=554
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?462835e8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");
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
if (rpm_check(release:"SL5", reference:"samba3x-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-client-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-common-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-debuginfo-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-debuginfo-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-doc-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-domainjoin-gui-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-swat-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-3.6.6-0.140.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-devel-3.6.6-0.140.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"libsmbclient-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libsmbclient-devel-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-client-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-common-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-debuginfo-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-debuginfo-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-doc-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-domainjoin-gui-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-swat-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-clients-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-devel-3.6.9-169.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-krb5-locator-3.6.9-169.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
