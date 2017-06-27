#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60500);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-3432", "CVE-2008-4101");

  script_name(english:"Scientific Linux Security Update : vim on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Several input sanitization flaws were found in Vim's keyword and tag
handling. If Vim looked up a document's maliciously crafted tag or
keyword, it was possible to execute arbitrary code as the user running
Vim. (CVE-2008-4101)

SL3 and SL4 Only: A heap-based overflow flaw was discovered in Vim's
expansion of file name patterns with shell wildcards. An attacker
could create a specially crafted file or directory name that, when
opened by Vim, caused the application to crash or, possibly, execute
arbitrary code. (CVE-2008-3432)

SL5 Only: Multiple security flaws were found in netrw.vim, the Vim
plug-in providing file reading and writing over the network. If a user
opened a specially crafted file or directory with the netrw plug-in,
it could result in arbitrary code execution as the user running Vim.
(CVE-2008-3076)

SL5 Only: A security flaw was found in zip.vim, the Vim plug-in that
handles ZIP archive browsing. If a user opened a ZIP archive using the
zip.vim plug-in, it could result in arbitrary code execution as the
user running Vim. (CVE-2008-3075)

SL5 Only: A security flaw was found in tar.vim, the Vim plug-in which
handles TAR archive browsing. If a user opened a TAR archive using the
tar.vim plug-in, it could result in arbitrary code execution as the
user runnin Vim. (CVE-2008-3074)

Several input sanitization flaws were found in various Vim system
functions. If a user opened a specially crafted file, it was possible
to execute arbitrary code as the user running Vim. (CVE-2008-2712)

Ulf H&auml;rnhammar, of Secunia Research, discovered a format string
flaw in Vim's help tag processor. If a user was tricked into executing
the 'helptags' command on malicious data, arbitrary code could be
executed with the permissions of the user running Vim. (CVE-2007-2953)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0811&L=scientific-linux-errata&T=0&P=1936
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3541c0de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 78, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
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
if (rpm_check(release:"SL3", reference:"vim-X11-6.3.046-0.30E.11")) flag++;
if (rpm_check(release:"SL3", reference:"vim-common-6.3.046-0.30E.11")) flag++;
if (rpm_check(release:"SL3", reference:"vim-enhanced-6.3.046-0.30E.11")) flag++;
if (rpm_check(release:"SL3", reference:"vim-minimal-6.3.046-0.30E.11")) flag++;

if (rpm_check(release:"SL4", reference:"vim-X11-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"SL4", reference:"vim-common-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"SL4", reference:"vim-enhanced-6.3.046-1.el4_7.5z")) flag++;
if (rpm_check(release:"SL4", reference:"vim-minimal-6.3.046-1.el4_7.5z")) flag++;

if (rpm_check(release:"SL5", reference:"vim-X11-7.0.109-4.el5_2.4z")) flag++;
if (rpm_check(release:"SL5", reference:"vim-common-7.0.109-4.el5_2.4z")) flag++;
if (rpm_check(release:"SL5", reference:"vim-enhanced-7.0.109-4.el5_2.4z")) flag++;
if (rpm_check(release:"SL5", reference:"vim-minimal-7.0.109-4.el5_2.4z")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
