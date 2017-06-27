#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61333);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2011-4940", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150");

  script_name(english:"Scientific Linux Security Update : python on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Python is an interpreted, interactive, object-oriented programming
language.

A denial of service flaw was found in the implementation of
associative arrays (dictionaries) in Python. An attacker able to
supply a large number of inputs to a Python application (such as HTTP
POST request parameters sent to a web application) that are used as
keys when inserting data into an array could trigger multiple hash
function collisions, making array operations take an excessive amount
of CPU time. To mitigate this issue, randomization has been added to
the hash function to reduce the chance of an attacker successfully
causing intentional collisions. (CVE-2012-1150)

Note: The hash randomization is not enabled by default as it may break
applications that incorrectly depend on dictionary ordering. To enable
the protection, the new 'PYTHONHASHSEED' environment variable or the
Python interpreter's '-R' command line option can be used. Refer to
the python(1) manual page for details.

The previous expat erratum must be installed with this update, which
adds hash randomization to the Expat library used by the Python
pyexpat module.

A flaw was found in the way the Python SimpleXMLRPCServer module
handled clients disconnecting prematurely. A remote attacker could use
this flaw to cause excessive CPU consumption on a server using
SimpleXMLRPCServer. (CVE-2012-0845)

A flaw was found in the way the Python SimpleHTTPServer module
generated directory listings. An attacker able to upload a file with a
specially crafted name to a server could possibly perform a cross-site
scripting (XSS) attack against victims visiting a listing page
generated by SimpleHTTPServer, for a directory containing the crafted
file (if the victims were using certain web browsers). (CVE-2011-4940)

A race condition was found in the way the Python distutils module set
file permissions during the creation of the .pypirc file. If a local
user had access to the home directory of another user who is running
distutils, they could use this flaw to gain access to that user's
.pypirc file, which can contain usernames and passwords for code
repositories. (CVE-2011-4944)

All Python users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1206&L=scientific-linux-errata&T=0&P=2093
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec112dab"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"python-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"SL6", reference:"python-debuginfo-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"SL6", reference:"python-devel-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"SL6", reference:"python-libs-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"SL6", reference:"python-test-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"SL6", reference:"python-tools-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"SL6", reference:"tkinter-2.6.6-29.el6_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
