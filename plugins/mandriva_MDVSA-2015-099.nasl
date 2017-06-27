#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:099. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82352);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2014-1932", "CVE-2014-1933", "CVE-2014-3007", "CVE-2014-3589", "CVE-2014-9601");
  script_xref(name:"MDVSA", value:"2015:099");

  script_name(english:"Mandriva Linux Security Advisory : python-pillow (MDVSA-2015:099)");
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
"Updated python-imaging packages fix security vulnerabilities :

Jakub Wilk discovered that temporary files were insecurely created
(via mktemp()) in the IptcImagePlugin.py, Image.py,
JpegImagePlugin.py, and EpsImagePlugin.py files of Python Imaging
Library. A local attacker could use this flaw to perform a symbolic
link attack to modify an arbitrary file accessible to the user running
an application that uses the Python Imaging Library (CVE-2014-1932).

Jakub Wilk discovered that temporary files created in the
JpegImagePlugin.py and EpsImagePlugin.py files of the Python Imaging
Library were passed to an external process. These could be viewed on
the command line, allowing an attacker to obtain the name and possibly
perform symbolic link attacks, allowing them to modify an arbitrary
file accessible to the user running an application that uses the
Python Imaging Library (CVE-2014-1933).

The Python Imaging Library is vulnerable to a denial of service attack
in the IcnsImagePlugin (CVE-2014-3589).

Python Image Library (PIL) 1.1.7 and earlier and Pillow 2.3 might
allow remote attackers to execute arbitrary commands via shell
metacharacters, due to an incomplete fix for CVE-2014-1932
(CVE-2014-3007).

Pillow before 2.7.0 and 2.6.2 allows remote attackers to cause a
denial of service via a compressed text chunk in a PNG image that has
a large size when it is decompressed (CVE-2014-9601)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0343.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0039.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-pillow-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-pillow-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-pillow-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-pillow-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-pillow-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-pillow-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-pillow-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-pillow-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python-pillow-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python-pillow-devel-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python-pillow-doc-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python-pillow-sane-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python-pillow-tk-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python3-pillow-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python3-pillow-devel-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python3-pillow-doc-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python3-pillow-sane-2.6.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python3-pillow-tk-2.6.2-1.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
