#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:204. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(83096);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/04/28 13:21:36 $");

  script_cve_id("CVE-2014-8242");
  script_xref(name:"MDVSA", value:"2015:204");

  script_name(english:"Mandriva Linux Security Advisory : librsync (MDVSA-2015:204)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated librsync packages fix security vulnerability :

librsync before 1.0.0 used a truncated MD4 strong check sum to match
blocks. However, MD4 is not cryptographically strong. It's possible
that an attacker who can control the contents of one part of a file
could use it to control other regions of the file, if it's transferred
using librsync/rdiff (CVE-2014-8242).

The change to fix this is not backward compatible with older versions
of librsync. Backward compatibility can be obtained using the new
rdiff sig --hash=md4 option or through specifying the signature magic
in the API, but this should not be used when either the old or new
file contain untrusted data.

Also, any applications that use the librsync library will need to be
recompiled against the updated library. The rdiff-backup packages have
been rebuilt for this reason."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0146.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rsync-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rsync2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rdiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rdiff-backup");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64rsync-devel-1.0.0-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64rsync2-1.0.0-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rdiff-1.0.0-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rdiff-backup-1.3.3-6.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
