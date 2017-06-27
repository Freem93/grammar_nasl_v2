#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-539.
#

include("compat.inc");

if (description)
{
  script_id(83978);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/04 13:39:50 $");

  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_xref(name:"ALAS", value:"2015-539");

  script_name(english:"Amazon Linux AMI : chrony (ALAS-2015-539)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"As reported upstream :

When NTP or cmdmon access was configured (from chrony.conf or via
authenticated cmdmon) with a subnet size that is indivisible by 4 and
an address that has nonzero bits in the 4-bit subnet remainder (e.g.
192.168.15.0/22 or f000::/3), the new setting was written to an
incorrect location, possibly outside the allocated array. An attacker
that has the command key and is allowed to access cmdmon (only
localhost is allowed by default) could exploit this to crash chronyd
or possibly execute arbitrary code with the privileges of the chronyd
process. (CVE-2015-1821)

When allocating memory to save unacknowledged replies to authenticated
command requests, the last 'next' pointer was not initialized to NULL.
When all allocated reply slots were used, the next reply could be
written to an invalid memory instead of allocating a new slot for it.
An attacker that has the command key and is allowed to access cmdmon
(only localhost is allowed by default) could exploit this to crash
chronyd or possibly execute arbitrary code with the privileges of the
chronyd process. (CVE-2015-1822)

An attacker knowing that NTP hosts A and B are peering with each other
(symmetric association) can send a packet with random timestamps to
host A with source address of B which will set the NTP state variables
on A to the values sent by the attacker. Host A will then send on its
next poll to B a packet with originate timestamp that doesn't match
the transmit timestamp of B and the packet will be dropped. If the
attacker does this periodically for both hosts, they won't be able to
synchronize to each other. Authentication using a symmetric key can
fully protect against this attack, but in implementations following
the NTPv3 (RFC 1305) or NTPv4 (RFC 5905) specification the state
variables were updated even when the authentication check failed and
the association was not protected. (CVE-2015-1853)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://chrony.tuxfamily.org/News.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-539.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update chrony' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:chrony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:chrony-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/04");
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
if (rpm_check(release:"ALA", reference:"chrony-1.31.1-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"chrony-debuginfo-1.31.1-1.13.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chrony / chrony-debuginfo");
}
