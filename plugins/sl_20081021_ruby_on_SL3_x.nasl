#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60485);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");

  script_name(english:"Scientific Linux Security Update : ruby on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"The Ruby DNS resolver library, resolv.rb, used predictable transaction
IDs and a fixed source port when sending DNS requests. A remote
attacker could use this flaw to spoof a malicious reply to a DNS
query. (CVE-2008-3905)

Ruby's XML document parsing module (REXML) was prone to a denial of
service attack via XML documents with large XML entity definitions
recursion. A specially crafted XML file could cause a Ruby application
using the REXML module to use an excessive amount of CPU and memory.
(CVE-2008-3790)

An insufficient 'taintness' check flaw was discovered in Ruby's DL
module, which provides direct access to the C language functions. An
attacker could use this flaw to bypass intended safe-level
restrictions by calling external C functions with the arguments from
an untrusted tainted inputs. (CVE-2008-3657)

A denial of service flaw was discovered in WEBrick, Ruby's HTTP server
toolkit. A remote attacker could send a specially crafted HTTP request
to a WEBrick server that would cause the server to use an excessive
amount of CPU time. (CVE-2008-3656)

A number of flaws were found in the safe-level restrictions in Ruby.
It was possible for an attacker to create a carefully crafted
malicious script that can allow the bypass of certain safe-level
restrictions. (CVE-2008-3655)

A denial of service flaw was found in Ruby's regular expression
engine. If a Ruby script tried to process a large amount of data via a
regular expression, it could cause Ruby to enter an infinite-loop and
crash. (CVE-2008-3443)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0810&L=scientific-linux-errata&T=0&P=2062
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39d0eb63"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/21");
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
if (rpm_check(release:"SL3", reference:"irb-1.6.8-13.el3")) flag++;
if (rpm_check(release:"SL3", reference:"ruby-1.6.8-13.el3")) flag++;
if (rpm_check(release:"SL3", reference:"ruby-devel-1.6.8-13.el3")) flag++;
if (rpm_check(release:"SL3", reference:"ruby-docs-1.6.8-13.el3")) flag++;
if (rpm_check(release:"SL3", reference:"ruby-libs-1.6.8-13.el3")) flag++;
if (rpm_check(release:"SL3", reference:"ruby-mode-1.6.8-13.el3")) flag++;
if (rpm_check(release:"SL3", reference:"ruby-tcltk-1.6.8-13.el3")) flag++;

if (rpm_check(release:"SL4", reference:"irb-1.8.1-7.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-1.8.1-7.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-devel-1.8.1-7.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-docs-1.8.1-7.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-libs-1.8.1-7.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-mode-1.8.1-7.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-tcltk-1.8.1-7.el4_7.1")) flag++;

if (rpm_check(release:"SL5", reference:"ruby-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-devel-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-docs-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-irb-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-libs-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-mode-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-rdoc-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-ri-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-tcltk-1.8.5-5.el5_2.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
