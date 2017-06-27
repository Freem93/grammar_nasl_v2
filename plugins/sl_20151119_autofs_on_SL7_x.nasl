#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87549);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2014-8169");

  script_name(english:"Scientific Linux Security Update : autofs on SL7.x x86_64");
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
"It was found that program-based automounter maps that used interpreted
languages such as Python used standard environment variables to locate
and load modules of those languages. A local attacker could
potentially use this flaw to escalate their privileges on the system.
(CVE-2014-8169)

Note: This issue has been fixed by adding the 'AUTOFS_' prefix to the
affected environment variables so that they are not used to subvert
the system. A configuration option ('force_standard_program_map_env')
to override this prefix and to use the environment variables without
the prefix has been added. In addition, warnings have been added to
the manual page and to the installed configuration file. Now, by
default the standard variables of the program map are provided only
with the prefix added to its name.

Notably, this update fixes the following bugs :

  - When the 'ls *' command was run in the root of an
    indirect mount, autofs attempted to literally mount the
    wildcard character (*) causing it to be added to the
    negative cache. If done before a valid mount, autofs
    then failed on further mount attempts inside the mount
    point, valid or not. This has been fixed, and wildcard
    map entries now function in the described situation.

  - When autofs encountered a syntax error consisting of a
    duplicate entry in a multimap entry, it reported an
    error and did not mount the map entry. With this update,
    autofs has been amended to report the problem in the log
    to alert the system administrator and use the last seen
    instance of the duplicate entry rather than fail.

  - In the ldap and sss lookup modules, the map reading
    functions did not distinguish between the 'no entry
    found' and 'service not available' errors. Consequently,
    when the 'service not available' response was returned
    from a master map read, autofs did not update the
    mounts. An 'entry not found' return does not prevent the
    map update, so the ldap and sss lookup modules were
    updated to distinguish between these two returns and now
    work as expected.

In addition, this update adds the following enhancement :

  - The description of the configuration parameter
    map_hash_table_size was missing from the autofs.conf(5)
    man page and its description in the configuration file
    comments was insufficient. A description of the
    parameter has been added to autofs.conf(5), and the
    configuration file comments have been updated."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=4175
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7732c09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs and / or autofs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"autofs-5.0.7-54.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"autofs-debuginfo-5.0.7-54.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
