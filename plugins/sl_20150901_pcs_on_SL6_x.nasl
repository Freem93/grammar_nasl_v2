#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85760);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");

  script_cve_id("CVE-2015-5189", "CVE-2015-5190");

  script_name(english:"Scientific Linux Security Update : pcs on SL6.x, SL7.x i386/x86_64");
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
"A command injection flaw was found in the pcsd web UI. An attacker
able to trick a victim that was logged in to the pcsd web UI into
visiting a specially crafted URL could use this flaw to execute
arbitrary code with root privileges on the server hosting the web UI.
(CVE-2015-5190)

A race condition was found in the way the pcsd web UI backend
performed authorization of user requests. An attacker could use this
flaw to send a request that would be evaluated as originating from a
different user, potentially allowing the attacker to perform actions
with permissions of a more privileged user. (CVE-2015-5189)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1509&L=scientific-linux-errata&F=&S=&P=5495
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?badd7c6c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected pcs, pcs-debuginfo and / or python-clufter
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"pcs-0.9.139-9.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"pcs-debuginfo-0.9.139-9.el6_7.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-0.9.137-13.el7_1.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-debuginfo-0.9.137-13.el7_1.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-clufter-0.9.137-13.el7_1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
