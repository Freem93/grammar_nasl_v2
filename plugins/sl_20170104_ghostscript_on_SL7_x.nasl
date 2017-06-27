#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(96302);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2013-5653", "CVE-2016-7977", "CVE-2016-7978", "CVE-2016-7979", "CVE-2016-8602");

  script_name(english:"Scientific Linux Security Update : ghostscript on SL7.x x86_64");
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

  - It was found that the ghostscript functions getenv,
    filenameforall and .libfile did not honor the -dSAFER
    option, usually used when processing untrusted
    documents, leading to information disclosure. A
    specially crafted postscript document could read
    environment variable, list directory and retrieve file
    content respectively, from the target. (CVE-2013-5653,
    CVE-2016-7977)

  - It was found that the ghostscript function .setdevice
    suffered a use- after-free vulnerability due to an
    incorrect reference count. A specially crafted
    postscript document could trigger code execution in the
    context of the gs process. (CVE-2016-7978)

  - It was found that the ghostscript function
    .initialize_dsc_parser did not validate its parameter
    before using it, allowing a type confusion flaw. A
    specially crafted postscript document could cause a
    crash code execution in the context of the gs process.
    (CVE-2016-7979)

  - It was found that ghostscript did not sufficiently check
    the validity of parameters given to the .sethalftone5
    function. A specially crafted postscript document could
    cause a crash, or execute arbitrary code in the context
    of the gs process. (CVE-2016-8602)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=409
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72203525"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-9.07-20.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-cups-9.07-20.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-debuginfo-9.07-20.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-devel-9.07-20.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"ghostscript-doc-9.07-20.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-gtk-9.07-20.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
