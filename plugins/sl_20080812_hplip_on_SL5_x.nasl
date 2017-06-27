#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60463);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-2940", "CVE-2008-2941");

  script_name(english:"Scientific Linux Security Update : hplip on SL5.x i386/x86_64");
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
"A flaw was discovered in the hplip alert-mailing functionality. A
local attacker could elevate their privileges by using specially
crafted packets to trigger alert mails, which are sent by the root
account. (CVE-2008-2940)

A flaw was discovered in the hpssd message parser. By sending
specially crafted packets, a local attacker could cause a denial of
service, stopping the hpssd process. (CVE-2008-2941)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0808&L=scientific-linux-errata&T=0&P=1168
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1c901cc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hpijs, hplip and / or libsane-hpaio packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
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
if (rpm_check(release:"SL5", reference:"hpijs-1.6.7-4.1.el5_2.4")) flag++;
if (rpm_check(release:"SL5", reference:"hplip-1.6.7-4.1.el5_2.4")) flag++;
if (rpm_check(release:"SL5", reference:"libsane-hpaio-1.6.7-4.1.el5_2.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
