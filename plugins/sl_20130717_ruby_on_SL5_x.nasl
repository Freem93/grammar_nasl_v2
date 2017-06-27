#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(68946);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/08/20 12:23:48 $");

  script_cve_id("CVE-2013-4073");

  script_name(english:"Scientific Linux Security Update : ruby on SL5.x, SL6.x i386/srpm/x86_64");
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
"A flaw was found in Ruby's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. An
attacker could potentially exploit this flaw to conduct
man-in-the-middle attacks to spoof SSL servers. Note that to exploit
this issue, an attacker would need to obtain a carefully-crafted
certificate signed by an authority that the client trusts.
(CVE-2013-4073)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1307&L=scientific-linux-errata&T=0&P=1435
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35ba4da8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");
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
if (rpm_check(release:"SL5", reference:"ruby-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-debuginfo-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-debuginfo-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-devel-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-docs-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-irb-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-libs-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-mode-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-rdoc-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-ri-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-tcltk-1.8.5-31.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"ruby-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-debuginfo-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-debuginfo-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-devel-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-docs-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-irb-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-libs-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-rdoc-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-ri-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-static-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-tcltk-1.8.7.352-12.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
