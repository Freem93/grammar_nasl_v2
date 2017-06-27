#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61031);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-1486");

  script_name(english:"Scientific Linux Security Update : libvirt on SL5.x, SL6.x i386/x86_64");
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
"A flaw was found in the way libvirtd handled error reporting for
concurrent connections. A remote attacker able to establish read-only
connections to libvirtd on a server could use this flaw to crash
libvirtd. (CVE-2011-1486)

libvirtd must be restarted ('service libvirtd restart') for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1105&L=scientific-linux-errata&T=0&P=209
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc1e36d1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/02");
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
if (rpm_check(release:"SL5", reference:"libvirt-0.8.2-15.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-devel-0.8.2-15.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-python-0.8.2-15.el5_6.4")) flag++;

if (rpm_check(release:"SL6", reference:"libvirt-0.8.1-27.el6_0.6")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.8.1-27.el6_0.6")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.8.1-27.el6_0.6")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.8.1-27.el6_0.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
