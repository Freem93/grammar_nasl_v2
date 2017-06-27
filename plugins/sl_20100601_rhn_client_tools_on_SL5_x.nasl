#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60797);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-1439");

  script_name(english:"Scientific Linux Security Update : rhn-client-tools on SL5.x i386/x86_64");
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
"It was discovered that rhn-client-tools set insecure permissions on
the loginAuth.pkl file, used to store session credentials for
authenticating connections to servers. A local, unprivileged user
could use these credentials to download packages they wouldn't
normally have permission to download. They could also manipulate
package or action lists associated with the system's profile.
(CVE-2010-1439)

Note: This package pulled in several other packages as dependencies in
order to fix all bugs and security holes."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1006&L=scientific-linux-errata&T=0&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b27b9241"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/01");
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
if (rpm_check(release:"SL5", reference:"hal-0.5.8.1-59.el5")) flag++;
if (rpm_check(release:"SL5", reference:"hal-devel-0.5.8.1-59.el5")) flag++;
if (rpm_check(release:"SL5", reference:"hal-gnome-0.5.8.1-59.el5")) flag++;
if (rpm_check(release:"SL5", reference:"m2crypto-0.16-6.el5.6")) flag++;
if (rpm_check(release:"SL5", reference:"pm-utils-0.99.3-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-dmidecode-3.10.8-4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rhn-check-0.4.20-33.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"rhn-client-tools-0.4.20-33.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"rhn-setup-0.4.20-33.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"rhn-setup-gnome-0.4.20-33.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"rhnlib-2.5.22-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"yum-rhn-plugin-0.5.4-15.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
