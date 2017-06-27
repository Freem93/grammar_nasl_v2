#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:227. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(69822);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2013-1633");
  script_bugtraq_id(61827);
  script_xref(name:"MDVSA", value:"2013:227");

  script_name(english:"Mandriva Linux Security Advisory : python-setuptools (MDVSA-2013:227)");
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
"A vulnerability has been discovered and corrected in
python-setuptools/python-virtualenv :

easy_install in setuptools before 0.7 uses HTTP to retrieve packages
from the PyPI repository, and does not perform integrity checks on
package contents, which allows man-in-the-middle attackers to execute
arbitrary code via a crafted response to the default use of the
product (CVE-2013-1633).

The updated python-setuptools packages has been upgraded to the 0.9.8
version and the python-virtualenv packages has been upgraded to the
1.10.1 version which is not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected python-pkg-resources, python-setuptools and / or
python-virtualenv packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-pkg-resources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-virtualenv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"python-pkg-resources-0.9.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"python-setuptools-0.9.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"python-virtualenv-1.10.1-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
