#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:076. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82329);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2013-7338", "CVE-2014-1912", "CVE-2014-2667", "CVE-2014-4616", "CVE-2014-4650");
  script_xref(name:"MDVSA", value:"2015:076");

  script_name(english:"Mandriva Linux Security Advisory : python3 (MDVSA-2015:076)");
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
"Updated python3 packages fix security vulnerabilities :

ZipExtFile.read goes into 100% CPU infinite loop on maliciously binary
edited zips (CVE-2013-7338).

A vulnerability was reported in Python's socket module, due to a
boundary error within the sock_recvfrom_into() function, which could
be exploited to cause a buffer overflow. This could be used to crash a
Python application that uses the socket.recvfrom_info() function or,
possibly, execute arbitrary code with the permissions of the user
running vulnerable Python code (CVE-2014-1912).

It was reported that a patch added to Python 3.2 caused a race
condition where a file created could be created with world read/write
permissions instead of the permissions dictated by the original umask
of the process. This could allow a local attacker that could win the
race to view and edit files created by a program using this call. Note
that prior versions of Python, including 2.x, do not include the
vulnerable _get_masked_mode() function that is used by os.makedirs()
when exist_ok is set to True (CVE-2014-2667).

Python are susceptible to arbitrary process memory reading by a user
or adversary due to a bug in the _json module caused by insufficient
bounds checking. The bug is caused by allowing the user to supply a
negative value that is used an an array index, causing the scanstring
function to access process memory outside of the string it is intended
to access (CVE-2014-4616).

The CGIHTTPServer Python module does not properly handle URL-encoded
path separators in URLs. This may enable attackers to disclose a CGI
script's source code or execute arbitrary scripts in the server's
document root (CVE-2014-4650)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0140.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0285.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter3-apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/27");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64python3-devel-3.3.2-14.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64python3.3-3.3.2-14.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python3-3.3.2-14.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python3-docs-3.3.2-14.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"tkinter3-3.3.2-14.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"tkinter3-apps-3.3.2-14.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
