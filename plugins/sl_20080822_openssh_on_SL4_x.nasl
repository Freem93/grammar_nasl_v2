#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60467);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/30 20:03:12 $");

  script_cve_id("CVE-2007-4752");

  script_name(english:"Scientific Linux Security Update : openssh on SL4.x, SL5.x i386/x86_64");
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
"These packages fix a low severity flaw in the way ssh handles X11
cookies when creating X11 forwarding connections. When ssh was unable
to create untrusted cookie, ssh used a trusted cookie instead,
possibly allowing the administrative user of a untrusted remote
server, or untrusted application run on the remote server, to gain
unintended access to a users local X server. (CVE-2007-4752)

To address concerns about these, and past openssh packages, we have
done an intensive review of the source rpm's of these, and past
openssh packages. Our conclusion is that these, and past packages have
NOT been compromised. Either at the source level, or the compiled
binary level."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0808&L=scientific-linux-errata&T=0&P=1788
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c977bcc1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/22");
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
if (rpm_check(release:"SL4", reference:"openssh-3.9p1-11.el4_7")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-askpass-3.9p1-11.el4_7")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-askpass-gnome-3.9p1-11.el4_7")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-clients-3.9p1-11.el4_7")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-server-3.9p1-11.el4_7")) flag++;

if (rpm_check(release:"SL5", reference:"openssh-4.3p2-26.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-askpass-4.3p2-26.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-clients-4.3p2-26.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-server-4.3p2-26.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
