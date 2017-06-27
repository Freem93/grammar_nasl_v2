#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:040. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(72564);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/19 11:50:45 $");

  script_cve_id("CVE-2013-4969");
  script_bugtraq_id(64552);
  script_xref(name:"MDVSA", value:"2014:040");

  script_name(english:"Mandriva Linux Security Advisory : puppet (MDVSA-2014:040)");
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
"A vulnerability has been discovered and corrected in puppet :

Puppet before 3.3.3 and 3.4 before 3.4.1 and Puppet Enterprise (PE)
before 2.8.4 and 3.1 before 3.1.1 allows local users to overwrite
arbitrary files via a symlink attack on unspecified files
(CVE-2013-4969).

The updated packages have been upgraded to the 2.7.25 version which is
not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://puppetlabs.com/security/cve/CVE-2013-4969"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:emacs-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:puppet-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"emacs-puppet-2.7.25-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"puppet-2.7.25-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"puppet-server-2.7.25-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"vim-puppet-2.7.25-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
