#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:070. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14820);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0590");
  script_xref(name:"MDKSA", value:"2004:070-1");

  script_name(english:"Mandrake Linux Security Advisory : super-freeswan (MDKSA-2004:070-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Thomas Walpuski discovered a vulnerability in the X.509 handling of
super-freeswan, openswan, strongSwan, and FreeS/WAN with the X.509
patch applied. This vulnerability allows an attacker to make up their
own Certificate Authority that can allow them to impersonate the
identity of a valid DN. As well, another hole exists in the CA
checking code that could create an endless loop in certain instances.

Mandrakesoft encourages all users who use FreeS/WAN or super-freeswan
to upgrade to the updated packages which are patched to correct these
flaws.

Update :

Due to a build error, the super-freeswan packages did not include the
pluto program. The updated packages fix this error."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.openswan.org/pipermail/dev/2004-June/000369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openswan.org/support/vuln/CVE-2004-0590/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected super-freeswan and / or super-freeswan-doc
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:super-freeswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:super-freeswan-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
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
if (rpm_check(release:"MDK10.0", reference:"super-freeswan-1.99.8-8.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"super-freeswan-doc-1.99.8-8.2.100mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
