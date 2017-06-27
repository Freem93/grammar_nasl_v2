#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:207. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(83099);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2015-3406",
    "CVE-2015-3407",
    "CVE-2015-3408",
    "CVE-2015-3409"
  );
  script_bugtraq_id(
    73935,
    73937
  );
  script_osvdb_id(
    121315,
    121316,
    121317,
    121318
  );
  script_xref(name:"MDVSA", value:"2015:207");

  script_name(english:"Mandriva Linux Security Advisory : perl-Module-Signature (MDVSA-2015:207)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated perl-Module-Signature package fixes the following security
vulnerabilities reported by John Lightsey :

Module::Signature could be tricked into interpreting the unsigned
portion of a SIGNATURE file as the signed portion due to faulty
parsing of the PGP signature boundaries.

When verifying the contents of a CPAN module, Module::Signature
ignored some files in the extracted tarball that were not listed in
the signature file. This included some files in the t/ directory that
would execute automatically during make test

When generating checksums from the signed manifest, Module::Signature
used two argument open() calls to read the files. This allowed
embedding arbitrary shell commands into the SIGNATURE file that would
execute during the signature verification process.

Several modules were loaded at runtime inside the extracted module
directory. Modules like Text::Diff are not guaranteed to be available
on all platforms and could be added to a malicious module so that they
would load from the '.' path in \@INC."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0160.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-Module-Signature package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-Module-Signature");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
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
if (rpm_check(release:"MDK-MBS1", reference:"perl-Module-Signature-0.730.0-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
