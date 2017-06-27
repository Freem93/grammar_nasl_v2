#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60260);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-3999", "CVE-2007-4135");
  script_xref(name:"TRA", value:"TRA-2007-07");

  script_name(english:"Scientific Linux Security Update : nfs-utils-lib on SL5.x i386/x86_64");
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
"Details :

Tenable Network Security discovered a stack-based buffer overflow flaw
in the RPC library used by nfs-utils-lib. A remote unauthenticated
attacker who can access an application linked against nfs-utils-lib
could trigger this flaw and cause the application to crash. On Red Hat
Enterprise Linux 5 it is not possible to exploit this flaw to run
arbitrary code as the overflow is blocked by FORTIFY_SOURCE.
(CVE-2007-3999)

Tony Ernst from SGI has discovered a flaw in the way nfsidmap maps
NFSv4 unknown uids. If an unknown user ID is encountered on an NFSv4
mounted filesystem, the files will default to being owned by 'root'
rather than 'nobody'. (CVE-2007-4135)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0710&L=scientific-linux-errata&T=0&P=187
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce716428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2007-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected nfs-utils-lib and / or nfs-utils-lib-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

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
if (rpm_check(release:"SL5", reference:"nfs-utils-lib-1.0.8-7.2.z2")) flag++;
if (rpm_check(release:"SL5", reference:"nfs-utils-lib-devel-1.0.8-7.2.z2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
