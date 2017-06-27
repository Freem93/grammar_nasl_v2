#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71201);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:30:40 $");

  script_cve_id("CVE-2013-0213", "CVE-2013-0214", "CVE-2013-4124");

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
"It was discovered that the Samba Web Administration Tool (SWAT) did
not protect against being opened in a web page frame. A remote
attacker could possibly use this flaw to conduct a clickjacking attack
against SWAT users or users with an active SWAT session.
(CVE-2013-0213)

A flaw was found in the Cross-Site Request Forgery (CSRF) protection
mechanism implemented in SWAT. An attacker with the knowledge of a
victim's password could use this flaw to bypass CSRF protections and
conduct a CSRF attack against the victim SWAT user. (CVE-2013-0214)

An integer overflow flaw was found in the way Samba handled an
Extended Attribute (EA) list provided by a client. A malicious client
could send a specially crafted EA list that triggered an overflow,
causing the server to loop and reprocess the list using an excessive
amount of memory. (CVE-2013-4124)

Note: This issue did not affect the default configuration of the Samba
server.

After installing this update, the smb service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=1306
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9144055b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libsmbclient-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsmbclient-devel-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libtevent-0.9.18-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libtevent-devel-0.9.18-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-client-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-common-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-debuginfo-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-doc-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-domainjoin-gui-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-swat-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-clients-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-devel-3.6.9-164.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-krb5-locator-3.6.9-164.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
