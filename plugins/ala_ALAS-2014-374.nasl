#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-374.
#

include("compat.inc");

if (description)
{
  script_id(78317);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-4616");
  script_xref(name:"ALAS", value:"2014-374");

  script_name(english:"Amazon Linux AMI : python-simplejson (ALAS-2014-374)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was reported that Python built-in _json module have a flaw
(insufficient bounds checking), which allows a local user to read
current process' arbitrary memory.

Quoting the upstream bug report :

'The sole prerequisites of this attack are that the attacker is able
to control or influence the two parameters of the default scanstring
function: the string to be decoded and the index.

The bug is caused by allowing the user to supply a negative index
value. The index value is then used directly as an index to an array
in the C code; internally the address of the array and its index are
added to each other in order to yield the address of the value that is
desired. However, by supplying a negative index value and adding this
to the address of the array, the processor's register value wraps
around and the calculated value will point to a position in memory
which isn't within the bounds of the supplied string, causing the
function to access other parts of the process memory.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.python.org/issue21529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-374.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python-simplejson' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-simplejson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-simplejson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"python-simplejson-3.5.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python-simplejson-debuginfo-3.5.3-1.7.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-simplejson / python-simplejson-debuginfo");
}
