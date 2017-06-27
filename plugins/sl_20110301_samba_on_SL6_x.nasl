#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60973);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-0719");

  script_name(english:"Scientific Linux Security Update : samba on SL6.x i386/x86_64");
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
"A flaw was found in the way Samba handled file descriptors. If an
attacker were able to open a large number of file descriptors on the
Samba server, they could flip certain stack bits to '1' values,
resulting in the Samba server (smbd) crashing. (CVE-2011-0719)

After installing this update, the smb service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=5539
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?409be306"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
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
if (rpm_check(release:"SL6", reference:"libsmbclient-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"libsmbclient-devel-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-client-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-common-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-doc-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-domainjoin-gui-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-swat-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-clients-3.5.4-68.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-devel-3.5.4-68.el6_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
