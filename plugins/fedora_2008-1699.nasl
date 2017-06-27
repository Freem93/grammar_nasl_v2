#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-1699.
#

include("compat.inc");

if (description)
{
  script_id(31104);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-0783", "CVE-2008-0784", "CVE-2008-0785", "CVE-2008-0786");
  script_bugtraq_id(27749);
  script_xref(name:"FEDORA", value:"2008-1699");

  script_name(english:"Fedora 8 : cacti-0.8.7b-1.fc8 (2008-1699)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes: * XSS vulnerabilities * Path disclosure vulnerabilities * SQL
injection vulnerabilities * HTTP response splitting vulnerabilities
bug#0000855: Unnecessary (and faulty) DEF generation for CF:AVERAGE
bug#0001083: Small visual fix for Cacti in 'View Cacti Log File'
bug#0001089: Graph xport modification to increase default rows output
bug#0001091: Poller incorrectly identifies unique hosts bug#0001093:
CLI Scripts bring MySQL down on large installations bug#0001094:
Filtering broken on Data Sources page bug#0001103: Fix looping poller
recache events bug#0001107: ss_fping.php 100% 'Pkt Loss' does not work
properly bug#0001114: Graphs with no template and/or no host cause
filtering errors on Graph Management page bug#0001115: View Poller
Cache does not show Data Sources that have no host bug#0001118: Graph
Generation fails if e.g. ifDescr contains some blanks bug#0001132:
TCP/UDP ping port ignored bug#0001133: Downed Device Detection: None
leads to database errors bug#0001134: update_host_status handles
ping_availability incorrectly bug#0001143: 'U' not allowed as min/max
RRD value bug#0001158: Deleted user causes error on user log viewer
bug#0001161: Re-assign duplicate radio button IDs bug#0001164: Add
HTML title attributes for certain pages bug#0001168:
ALL_DATA_SOURCES_NODUPS includes DUPs? SIMILAR_DATA_SOURCES_DUPS is
available again bug: Cacti does not guarentee RRA consolidation
functions exist in RRA's bug: Alert on changing logarithmic scaling
removed bug: add_hosts.php did not accept privacy protocol security:
Fix several security vulnerabilities feature: show basic RRDtool graph
options on Graph Template edit feature: Add additional logging to
Graph Xport feature: Add rows dropdown to devices, graphs and data
sources feature: Add device_id and event count to devices feature: Add
ids to devices, graphs and data sources pages feature: Add database
repair utility

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=432758"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007951.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3090b9fb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cacti package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 89, 94, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"cacti-0.8.7b-1.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti");
}
