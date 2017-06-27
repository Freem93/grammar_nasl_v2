#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61123);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2010-0547", "CVE-2010-0787", "CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694");

  script_name(english:"Scientific Linux Security Update : samba on SL4.x, SL5.x i386/x86_64");
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
"Samba is a suite of programs used by machines to share files,
printers, and other information.

A cross-site scripting (XSS) flaw was found in the password change
page of the Samba Web Administration Tool (SWAT). If a remote attacker
could trick a user, who was logged into the SWAT interface, into
visiting a specially crafted URL, it would lead to arbitrary web
script execution in the context of the user's SWAT session.
(CVE-2011-2694)

It was found that SWAT web pages did not protect against Cross-Site
Request Forgery (CSRF) attacks. If a remote attacker could trick a
user, who was logged into the SWAT interface, into visiting a
specially crafted URL, the attacker could perform Samba configuration
changes with the privileges of the logged in user. (CVE-2011-2522)

A race condition flaw was found in the way the mount.cifs tool mounted
CIFS (Common Internet File System) shares. If mount.cifs had the
setuid bit set, a local attacker could conduct a symbolic link attack
to trick mount.cifs into mounting a share over an arbitrary directory
they were otherwise not allowed to mount to, possibly allowing them to
escalate their privileges. (CVE-2010-0787)

It was found that the mount.cifs tool did not properly handle share or
directory names containing a newline character. If mount.cifs had the
setuid bit set, a local attacker could corrupt the mtab (mounted file
systems table) file via a specially crafted CIFS share mount request.
(CVE-2010-0547)

It was found that the mount.cifs tool did not handle certain errors
correctly when updating the mtab file. If mount.cifs had the setuid
bit set, a local attacker could corrupt the mtab file by setting a
small file size limit before running mount.cifs. (CVE-2011-1678)

Note: mount.cifs from the samba packages distributed by Red Hat does
not have the setuid bit set. We recommend that administrators do not
manually set the setuid bit for mount.cifs.

Users of Samba are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the smb service will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=3574
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52aad1a0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/29");
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
if (rpm_check(release:"SL4", reference:"samba-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"SL4", reference:"samba-client-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"SL4", reference:"samba-common-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"SL4", reference:"samba-swat-3.0.33-0.34.el4")) flag++;

if (rpm_check(release:"SL5", reference:"libsmbclient-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"libsmbclient-devel-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"samba-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"samba-client-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"samba-common-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"samba-swat-3.0.33-3.29.el5_7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
