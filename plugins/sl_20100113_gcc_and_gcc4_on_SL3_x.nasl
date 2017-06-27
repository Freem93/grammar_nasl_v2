#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60722);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/06 11:47:00 $");

  script_cve_id("CVE-2009-3736");

  script_name(english:"Scientific Linux Security Update : gcc and gcc4 on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-3736 libtool: libltdl may load and execute code from a
library in the current directory

A flaw was found in the way GNU Libtool's libltdl library looked for
libraries to load. It was possible for libltdl to load a malicious
library from the current working directory. In certain configurations,
if a local attacker is able to trick a local user into running a Java
application (which uses a function to load native libraries, such as
System.loadLibrary) from within an attacker-controlled directory
containing a malicious library or module, the attacker could possibly
execute arbitrary code with the privileges of the user running the
Java application. (CVE-2009-3736)

All running Java applications using libgcj must be restarted for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1001&L=scientific-linux-errata&T=0&P=2048
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c2db746"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"cpp-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-c++-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-g77-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-gnat-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-java-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-objc-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libf2c-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libgcc-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libgcj-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libgcj-devel-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libgnat-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libobjc-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libstdc++-3.2.3-60")) flag++;
if (rpm_check(release:"SL3", reference:"libstdc++-devel-3.2.3-60")) flag++;

if (rpm_check(release:"SL4", reference:"cpp-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc-c++-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc-g77-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc-gnat-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc-java-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc-objc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc4-c++-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc4-gfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"gcc4-java-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libf2c-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgcc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgcj-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgcj-devel-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgcj4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgcj4-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgcj4-src-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgnat-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libgomp-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libmudflap-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libmudflap-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libobjc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libstdc++-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libstdc++-devel-3.4.6-11.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"cpp-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-c++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-gfortran-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-gnat-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-java-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-objc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-objc++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libgcc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libgcj-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libgcj-devel-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libgcj-src-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libgfortran-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libgnat-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libmudflap-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libmudflap-devel-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libobjc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libstdc++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"SL5", reference:"libstdc++-devel-4.1.2-46.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
