#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:112. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15547);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/06/02 23:43:55 $");

  script_cve_id("CVE-2004-0918");
  script_xref(name:"MDKSA", value:"2004:112");

  script_name(english:"Mandrake Linux Security Advisory : squid (MDKSA-2004:112)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"iDEFENSE discovered a Denial of Service vulnerability in squid version
2.5.STABLE6 and previous. The problem is due to an ASN1 parsing error
where certain header length combinations can slip through the
validations performed by the ASN1 parser, leading to the server
assuming there is heap corruption or some other exceptional condition,
and closing all current connections then restarting.

Squid 2.5.STABLE7 has been released to address this issue; the
provided packages are patched to fix the issue."
  );
  # http://www.idefense.com/application/poi/display?id=152&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d34310cf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"squid-2.5.STABLE4-2.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"squid-2.5.STABLE6-2.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"squid-2.5.STABLE3-3.4.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
