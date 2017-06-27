#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:161. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82414);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2014-6585",
    "CVE-2014-6591",
    "CVE-2014-7923",
    "CVE-2014-7926",
    "CVE-2014-7940"
  );
  script_bugtraq_id(
    72173,
    72175,
    72288
  );
  script_osvdb_id(
    117232,
    117233,
    117380,
    117383,
    117397
  );
  script_xref(name:"MDVSA", value:"2015:161");
  script_xref(name:"MDVSA", value:"2015:161-1");

  script_name(english:"Mandriva Linux Security Advisory : icu (MDVSA-2015:161-1)");
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
"Updated icu packages fix security vulnerabilities :

The Regular Expressions package in International Components for
Unicode (ICU) 52 before SVN revision 292944 allows remote attackers to
cause a denial of service (memory corruption) or possibly have
unspecified other impact via vectors related to a zero-length
quantifier or look-behind expression (CVE-2014-7923, CVE-2014-7926).

The collator implementation in i18n/ucol.cpp in International
Components for Unicode (ICU) 52 through SVN revision 293126 does not
initialize memory for a data structure, which allows remote attackers
to cause a denial of service or possibly have unspecified other impact
via a crafted character sequence (CVE-2014-7940).

It was discovered that ICU incorrectly handled memory operations when
processing fonts. If an application using ICU processed crafted data,
an attacker could cause it to crash or potentially execute arbitrary
code with the privileges of the user invoking the program
(CVE-2014-6585, CVE-2014-6591)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0102.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icu-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icu-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64icu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64icu48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64icu52");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"icu-4.8.1.1-3.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"icu-doc-4.8.1.1-3.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64icu-devel-4.8.1.1-3.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64icu48-4.8.1.1-3.2.mbs1")) flag++;

if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"icu-52.1-2.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"icu-data-52.1-2.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"icu-doc-52.1-2.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64icu-devel-52.1-2.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64icu52-52.1-2.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
