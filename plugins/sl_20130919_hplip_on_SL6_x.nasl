#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70014);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/24 11:02:01 $");

  script_cve_id("CVE-2013-4325");

  script_name(english:"Scientific Linux Security Update : hplip on SL6.x i386/x86_64");
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
"HPLIP communicated with PolicyKit for authorization via a D-Bus API
that is vulnerable to a race condition. This could lead to intended
PolicyKit authorizations being bypassed. This update modifies HPLIP to
communicate with PolicyKit via a different API that is not vulnerable
to the race condition. (CVE-2013-4325)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1309&L=scientific-linux-errata&T=0&P=1455
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49821f3f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"hpijs-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-common-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-debuginfo-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-gui-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-libs-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libsane-hpaio-3.12.4-4.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
