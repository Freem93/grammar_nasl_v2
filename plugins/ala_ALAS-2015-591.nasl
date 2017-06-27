#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-591.
#

include("compat.inc");

if (description)
{
  script_id(85749);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/10/05 13:44:21 $");

  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");
  script_xref(name:"ALAS", value:"2015-591");

  script_name(english:"Amazon Linux AMI : sqlite (ALAS-2015-591)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way SQLite handled dequoting of
collation-sequence names. A local attacker could submit a specially
crafted COLLATE statement that would crash the SQLite process, or have
other unspecified impacts. (CVE-2015-3414)

It was found that SQLite's sqlite3VdbeExec() function did not properly
implement comparison operators. A local attacker could submit a
specially crafted CHECK statement that would crash the SQLite process,
or have other unspecified impacts. (CVE-2015-3415)

It was found that SQLite's sqlite3VXPrintf() function did not properly
handle precision and width values during floating-point conversions. A
local attacker could submit a specially crafted SELECT statement that
would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3416)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-591.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update sqlite' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sqlite-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"lemon-3.7.17-6.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sqlite-3.7.17-6.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sqlite-debuginfo-3.7.17-6.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sqlite-devel-3.7.17-6.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sqlite-doc-3.7.17-6.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sqlite-tcl-3.7.17-6.13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lemon / sqlite / sqlite-debuginfo / sqlite-devel / sqlite-doc / etc");
}
