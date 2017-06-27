#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:097. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61956);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-4944",
    "CVE-2012-0845",
    "CVE-2012-0876",
    "CVE-2012-1150"
  );
  script_bugtraq_id(
    49778,
    51239,
    51996,
    52379,
    52732
  );
  script_osvdb_id(
    74829,
    79249,
    80009,
    80892,
    82462
  );
  script_xref(name:"MDVSA", value:"2012:097");

  script_name(english:"Mandriva Linux Security Advisory : python (MDVSA-2012:097)");
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
"Multiple vulnerabilities has been discovered and corrected in python :

The _ssl module would always disable the CBC IV attack countermeasure
(CVE-2011-3389).

A race condition was found in the way the Python distutils module set
file permissions during the creation of the .pypirc file. If a local
user had access to the home directory of another user who is running
distutils, they could use this flaw to gain access to that user's
.pypirc file, which can contain usernames and passwords for code
repositories (CVE-2011-4944).

A flaw was found in the way the Python SimpleXMLRPCServer module
handled clients disconnecting prematurely. A remote attacker could use
this flaw to cause excessive CPU consumption on a server using
SimpleXMLRPCServer (CVE-2012-0845).

Hash table collisions CPU usage DoS for the embedded copy of expat
(CVE-2012-0876).

A denial of service flaw was found in the implementation of
associative arrays (dictionaries) in Python. An attacker able to
supply a large number of inputs to a Python application (such as HTTP
POST request parameters sent to a web application) that are used as
keys when inserting data into an array could trigger multiple hash
function collisions, making array operations take an excessive amount
of CPU time. To mitigate this issue, randomization has been added to
the hash function to reduce the chance of an attacker successfully
causing intentional collisions (CVE-2012-1150).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter-apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64python-devel-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64python2.7-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libpython-devel-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libpython2.7-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"python-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"python-docs-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"tkinter-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"tkinter-apps-2.7.2-2.2-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
