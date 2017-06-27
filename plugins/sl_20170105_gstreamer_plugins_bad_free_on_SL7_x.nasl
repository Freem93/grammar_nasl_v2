#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(96332);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:05 $");

  script_cve_id("CVE-2016-9445", "CVE-2016-9447", "CVE-2016-9809");

  script_name(english:"Scientific Linux Security Update : gstreamer-plugins-bad-free on SL7.x x86_64");
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
"Security Fix(es) :

  - An integer overflow flaw, leading to a heap-based buffer
    overflow, was found in GStreamer's VMware VMnc video
    file format decoding plug-in. A remote attacker could
    use this flaw to cause an application using GStreamer to
    crash or, potentially, execute arbitrary code with the
    privileges of the user running the application.
    (CVE-2016-9445)

  - A memory corruption flaw was found in GStreamer's
    Nintendo NSF music file format decoding plug-in. A
    remote attacker could use this flaw to cause an
    application using GStreamer to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running the application. (CVE-2016-9447)

  - An out-of-bounds heap read flaw was found in GStreamer's
    H.264 parser. A remote attacker could use this flaw to
    cause an application using GStreamer to crash.
    (CVE-2016-9809)

Note: This update removes the vulnerable Nintendo NSF plug-in."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=1196
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afbd1214"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-0.10.23-22.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-debuginfo-0.10.23-22.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-devel-0.10.23-22.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-devel-docs-0.10.23-22.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
