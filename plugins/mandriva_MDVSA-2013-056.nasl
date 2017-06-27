#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:056. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66070);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2011-3102",
    "CVE-2012-2807",
    "CVE-2012-5134",
    "CVE-2013-0338"
  );
  script_bugtraq_id(
    53540,
    54718,
    56684,
    58180
  );
  script_osvdb_id(
    81964,
    83266,
    87882,
    90631
  );
  script_xref(name:"MDVSA", value:"2013:056");

  script_name(english:"Mandriva Linux Security Advisory : libxml2 (MDVSA-2013:056)");
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
"Multiple vulnerabilities was found and corrected in libxml2 :

A heap-buffer overflow was found in the way libxml2 decoded certain
XML entitites. A remote attacker could provide a specially crafted XML
file, which once opened in an application linked against libxml would
cause that application to crash, or, potentially, execute arbitrary
code with the privileges of the user running the application
(CVE-2012-5134).

A denial of service flaw was found in the way libxml2 performed string
substitutions when entity values for entity references replacement was
enabled. A remote attacker could provide a specially crafted XML file
that, when processed by an application linked against libxml2, would
lead to excessive CPU consumption (CVE-2013-0338).

An Off-by-one error in libxml2 allows remote attackers to cause a
denial of service (out-of-bounds write) or possibly have unspecified
other impact via unknown vectors (CVE-2011-3102).

Multiple integer overflows in libxml2, on 64-bit Linux platforms allow
remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors (CVE-2012-2807).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=912400"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xml2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64xml2-devel-2.7.8-14.20120229.2.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64xml2_2-2.7.8-14.20120229.2.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"libxml2-python-2.7.8-14.20120229.2.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"libxml2-utils-2.7.8-14.20120229.2.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
