#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:113. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66125);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/09/16 13:25:42 $");

  script_cve_id("CVE-2012-5195", "CVE-2012-6329", "CVE-2013-1667");
  script_bugtraq_id(56287, 56950, 58311);
  script_xref(name:"MDVSA", value:"2013:113");
  script_xref(name:"MGASA", value:"2012-0352");
  script_xref(name:"MGASA", value:"2013-0032");
  script_xref(name:"MGASA", value:"2013-0094");

  script_name(english:"Mandriva Linux Security Advisory : perl (MDVSA-2013:113)");
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
"Updated perl packages fix security vulnerability :

It was discovered that Perl's 'x' string repeat operator is vulnerable
to a heap-based buffer overflow. An attacker could use this to execute
arbitrary code (CVE-2012-5195).

The _compile function in Maketext.pm in the Locale::Maketext
implementation in Perl before 5.17.7 does not properly handle
backslashes and fully qualified method names during compilation of
bracket notation, which allows context-dependent attackers to execute
arbitrary commands via crafted input to an application that accepts
translation strings from users (CVE-2012-6329).

In order to prevent an algorithmic complexity attack against its
hashing mechanism, perl will sometimes recalculate keys and
redistribute the contents of a hash. This mechanism has made perl
robust against attacks that have been demonstrated against other
systems. Research by Yves Orton has recently uncovered a flaw in the
rehashing code which can result in pathological behavior. This flaw
could be exploited to carry out a denial of service attack against
code that uses arbitrary user input as hash keys. Because using
user-provided strings as hash keys is a very common operation, we urge
users of perl to update their perl executable as soon as possible.
Updates to address this issue have bene pushed to main-5.8,
maint-5.10, maint-5.12, maint-5.14, and maint-5.16 branches today.
Vendors* were informed of this problem two weeks ago and are expected
to be shipping updates today (or otherwise very soon) (CVE-2013-1667)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki 5.1.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-Locale-Maketext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-5.14.2-8.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"perl-Locale-Maketext-1.220.0-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-base-5.14.2-8.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-devel-5.14.2-8.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"perl-doc-5.14.2-8.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
