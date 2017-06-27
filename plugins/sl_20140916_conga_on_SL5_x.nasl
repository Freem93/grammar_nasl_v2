#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78417);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/14 10:52:33 $");

  script_cve_id("CVE-2012-5485", "CVE-2012-5486", "CVE-2012-5488", "CVE-2012-5497", "CVE-2012-5498", "CVE-2012-5499", "CVE-2012-5500", "CVE-2013-6496", "CVE-2014-3521");

  script_name(english:"Scientific Linux Security Update : conga on SL5.x i386/x86_64");
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
"It was discovered that Plone, included as a part of luci, did not
properly protect the administrator interface (control panel). A remote
attacker could use this flaw to inject a specially crafted Python
statement or script into Plone's restricted Python sandbox that, when
the administrator interface was accessed, would be executed with the
privileges of that administrator user. (CVE-2012-5485)

It was discovered that Plone, included as a part of luci, did not
properly sanitize HTTP headers provided within certain URL requests. A
remote attacker could use a specially crafted URL that, when
processed, would cause the injected HTTP headers to be returned as a
part of the Plone HTTP response, potentially allowing the attacker to
perform other more advanced attacks. (CVE-2012-5486)

Multiple information leak flaws were found in the way conga processed
luci site extension-related URL requests. A remote, unauthenticated
attacker could issue a specially crafted HTTP request that, when
processed, would result in unauthorized information disclosure.
(CVE-2013-6496)

It was discovered that various components in the luci site extension-
related URLs were not properly restricted to administrative users. A
remote, authenticated attacker could escalate their privileges to
perform certain actions that should be restricted to administrative
users, such as adding users and systems, and viewing log data.
(CVE-2014-3521)

It was discovered that Plone, included as a part of luci, did not
properly protect the privilege of running RestrictedPython scripts. A
remote attacker could use a specially crafted URL that, when
processed, would allow the attacker to submit and perform expensive
computations or, in conjunction with other attacks, be able to access
or alter privileged information. (CVE-2012-5488)

It was discovered that Plone, included as a part of luci, did not
properly enforce permissions checks on the membership database. A
remote attacker could use a specially crafted URL that, when
processed, could allow the attacker to enumerate user account names.
(CVE-2012-5497)

It was discovered that Plone, included as a part of luci, did not
properly handle the processing of requests for certain collections. A
remote attacker could use a specially crafted URL that, when
processed, would lead to excessive I/O and/or cache resource
consumption. (CVE-2012-5498)

It was discovered that Plone, included as a part of luci, did not
properly handle the processing of very large values passed to an
internal utility function. A remote attacker could use a specially
crafted URL that, when processed, would lead to excessive memory
consumption. (CVE-2012-5499)

It was discovered that Plone, included as a part of luci, allowed a
remote anonymous user to change titles of content items due to
improper permissions checks. (CVE-2012-5500)

The CVE-2014-3521 issue was discovered by Radek Steiger of Red Hat,
and the CVE-2013-6496 issue was discovered by Jan Pokorny of Red Hat.

Users are directed to the Scientific Linux 5.11 Technical Notes,
linked to in the References section, for information on the most
significant of these changes

After installing this update, the luci and ricci services will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=432
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f5e2d66"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga-debuginfo, luci and / or ricci packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"conga-debuginfo-0.12.2-81.el5")) flag++;
if (rpm_check(release:"SL5", reference:"luci-0.12.2-81.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ricci-0.12.2-81.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
