#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85190);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2015/09/13 04:38:20 $");

  script_cve_id("CVE-2015-4620");

  script_name(english:"Scientific Linux Security Update : bind on SL6.x i386/x86_64");
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
"A flaw was found in the way BIND performed DNSSEC validation. An
attacker able to make BIND (functioning as a DNS resolver with DNSSEC
validation enabled) resolve a name in an attacker-controlled domain
could cause named to exit unexpectedly with an assertion failure.
(CVE-2015-4620)

After installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=746
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca08e71c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"bind-9.8.2-0.37.rc1.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-chroot-9.8.2-0.37.rc1.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-debuginfo-9.8.2-0.37.rc1.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-devel-9.8.2-0.37.rc1.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-libs-9.8.2-0.37.rc1.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-sdb-9.8.2-0.37.rc1.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-utils-9.8.2-0.37.rc1.el6_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
