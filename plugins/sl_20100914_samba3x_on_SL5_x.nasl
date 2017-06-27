#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60856);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-3069");

  script_name(english:"Scientific Linux Security Update : samba3x on SL5.x i386/x86_64");
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
"NOTE: This errata went out 2010-09-15, but this email was not sent.

A missing array boundary checking flaw was found in the way Samba
parsed the binary representation of Windows security identifiers
(SIDs). A malicious client could send a specially crafted SMB request
to the Samba server, resulting in arbitrary code execution with the
privileges of the Samba server (smbd). (CVE-2010-3069)

After installing this update, the smb service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1009&L=scientific-linux-errata&T=0&P=1640
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ed56815"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libtalloc-1.2.0-52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"libtalloc-devel-1.2.0-52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"libtdb-1.1.2-52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"libtdb-devel-1.1.2-52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-client-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-common-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-doc-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-domainjoin-gui-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-swat-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"samba3x-winbind-devel-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"tdb-tools-1.1.2-52.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
